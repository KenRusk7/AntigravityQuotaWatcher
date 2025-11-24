/**
 * Windows-specific process detection implementation.
 * Uses wmic (fallback to PowerShell if unavailable) and netstat commands.
 */

import { IPlatformStrategy } from './platformDetector';

export class WindowsProcessDetector implements IPlatformStrategy {
    private usePowerShell: boolean = false;

    /**
     * 设置是否使用 PowerShell 模式
     * 当 WMIC 不可用时(Windows 10 21H1+ / Windows 11),自动降级到 PowerShell
     */
    setUsePowerShell(value: boolean): void {
        this.usePowerShell = value;
    }

    /**
     * 获取是否使用 PowerShell 模式
     */
    isUsingPowerShell(): boolean {
        return this.usePowerShell;
    }

    /**
     * Get command to list Windows processes.
     * 优先使用 wmic,如果不可用则使用 PowerShell
     */
    getProcessListCommand(processName: string): string {
        if (this.usePowerShell) {
            // PowerShell 命令:使用 Get-CimInstance 获取进程信息并输出 JSON
            return `powershell -NoProfile -Command "Get-CimInstance Win32_Process -Filter \\"name='${processName}'\\" | Select-Object ProcessId,CommandLine | ConvertTo-Json"`;
        } else {
            // WMIC 命令(传统方式)
            return `wmic process where "name='${processName}'" get ProcessId,CommandLine /format:list`;
        }
    }

    /**
     * Parse process output to extract process information.
     * 支持 WMIC 和 PowerShell 两种输出格式
     * 
     * WMIC 格式:
     *   CommandLine=...--extension_server_port=1234 --csrf_token=abc123...
     *   ProcessId=5678
     * 
     * PowerShell JSON 格式:
     *   {"ProcessId":5678,"CommandLine":"...--extension_server_port=1234 --csrf_token=abc123..."}
     *   或数组: [{"ProcessId":5678,"CommandLine":"..."}]
     */
    parseProcessInfo(stdout: string): {
        pid: number;
        extensionPort: number;
        csrfToken: string;
    } | null {
        // 尝试解析 PowerShell JSON 输出
        if (this.usePowerShell || stdout.trim().startsWith('{') || stdout.trim().startsWith('[')) {
            try {
                let data = JSON.parse(stdout.trim());
                // 如果是数组,取第一个元素
                if (Array.isArray(data)) {
                    if (data.length === 0) {
                        return null;
                    }
                    data = data[0];
                }

                const commandLine = data.CommandLine || '';
                const pid = data.ProcessId;

                if (!pid) {
                    return null;
                }

                const portMatch = commandLine.match(/--extension_server_port[=\s]+(\d+)/);
                const tokenMatch = commandLine.match(/--csrf_token[=\s]+([a-f0-9\-]+)/i);

                if (!tokenMatch || !tokenMatch[1]) {
                    return null;
                }

                const extensionPort = portMatch && portMatch[1] ? parseInt(portMatch[1], 10) : 0;
                const csrfToken = tokenMatch[1];

                return { pid, extensionPort, csrfToken };
            } catch (e) {
                // JSON 解析失败,继续尝试 WMIC 格式
            }
        }

        // 解析 WMIC 输出格式
        const portMatch = stdout.match(/--extension_server_port[=\s]+(\d+)/);
        const tokenMatch = stdout.match(/--csrf_token[=\s]+([a-f0-9\-]+)/i);
        const pidMatch = stdout.match(/ProcessId=(\d+)/);

        if (!pidMatch || !pidMatch[1]) {
            return null;
        }

        if (!tokenMatch || !tokenMatch[1]) {
            return null;
        }

        const pid = parseInt(pidMatch[1], 10);
        const extensionPort = portMatch && portMatch[1] ? parseInt(portMatch[1], 10) : 0;
        const csrfToken = tokenMatch[1];

        return { pid, extensionPort, csrfToken };
    }

    /**
     * Get command to list ports for a specific process using netstat.
     */
    getPortListCommand(pid: number): string {
        return `netstat -ano | findstr "${pid}" | findstr "LISTENING"`;
    }

    /**
     * Parse netstat output to extract listening ports.
     * Expected format:
     *   TCP    127.0.0.1:2873         0.0.0.0:0              LISTENING       4412
     */
    parseListeningPorts(stdout: string): number[] {
        const portRegex = /127\.0\.0\.1:(\d+)\s+0\.0\.0\.0:0\s+LISTENING/g;
        const ports: number[] = [];
        let match;

        while ((match = portRegex.exec(stdout)) !== null) {
            const port = parseInt(match[1], 10);
            if (!ports.includes(port)) {
                ports.push(port);
            }
        }

        return ports.sort((a, b) => a - b);
    }

    /**
     * Get Windows-specific error messages.
     */
    getErrorMessages(): {
        processNotFound: string;
        commandNotAvailable: string;
        requirements: string[];
    } {
        return {
            processNotFound: 'language_server process not found',
            commandNotAvailable: this.usePowerShell
                ? 'PowerShell command failed; please check system permissions'
                : 'wmic/PowerShell command unavailable; please check the system environment',
            requirements: [
                'Antigravity is running',
                'language_server_windows_x64.exe process is running',
                this.usePowerShell
                    ? 'The system has permission to run PowerShell and netstat commands'
                    : 'The system has permission to run wmic/PowerShell and netstat commands (auto-fallback supported)'
            ]
        };
    }
}

