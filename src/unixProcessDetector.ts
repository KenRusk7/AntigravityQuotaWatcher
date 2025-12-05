/**
 * Unix-based (macOS/Linux) process detection implementation.
 * Uses ps and lsof/netstat commands.
 */

declare const process: any;
import { IPlatformStrategy } from './platformDetector';

export class UnixProcessDetector implements IPlatformStrategy {
    private platform: NodeJS.Platform;

    constructor(platform: NodeJS.Platform) {
        this.platform = platform;
    }

    /**
     * Get command to list Unix processes using ps and grep.
     */
    getProcessListCommand(processName: string): string {
        // Use ps -ww -eo pid,ppid,args to get PID, PPID and full command line
        // -ww: unlimited width (avoid truncation)
        // -e: select all processes
        // -o: user-defined format
        return `ps -ww -eo pid,ppid,args | grep "${processName}" | grep -v grep`;
    }

    parseProcessInfo(stdout: string): {
        pid: number;
        extensionPort: number;
        csrfToken: string;
    } | null {
        if (!stdout || stdout.trim().length === 0) {
            return null;
        }

        const lines = stdout.trim().split('\n');
        const currentPid = process.pid;
        const candidates: Array<{ pid: number; ppid: number; extensionPort: number; csrfToken: string }> = [];

        for (const line of lines) {
            // Format: PID PPID COMMAND...
            const parts = line.trim().split(/\s+/);
            if (parts.length < 3) {
                continue;
            }

            const pid = parseInt(parts[0], 10);
            const ppid = parseInt(parts[1], 10);

            // Reconstruct command line (it might contain spaces)
            const cmd = parts.slice(2).join(' ');

            if (isNaN(pid) || isNaN(ppid)) {
                continue;
            }

            const portMatch = cmd.match(/--extension_server_port[=\s]+(\d+)/);
            const tokenMatch = cmd.match(/--csrf_token[=\s]+([a-f0-9\-]+)/i);

            if (tokenMatch && tokenMatch[1]) {
                const extensionPort = portMatch && portMatch[1] ? parseInt(portMatch[1], 10) : 0;
                const csrfToken = tokenMatch[1];
                candidates.push({ pid, ppid, extensionPort, csrfToken });
            }
        }

        if (candidates.length === 0) {
            return null;
        }

        // 1. Prefer the process that is a direct child of the current process (extension host)
        const child = candidates.find(c => c.ppid === currentPid);
        if (child) {
            return child;
        }

        // 2. Fallback: return the first candidate found (legacy behavior)
        // This handles cases where the process hierarchy might be different (e.g. intermediate shell)
        return candidates[0];
    }

    /**
     * Get command to list ports for a specific process.
     * Tries lsof first (more reliable), falls back to netstat.
     */
    getPortListCommand(pid: number): string {
        // lsof is more reliable and available on both macOS and Linux
        // -P: no port name resolution
        // -a: AND the conditions
        // -n: no hostname resolution
        // -p: process ID
        // -i: internet connections only
        return `lsof -Pan -p ${pid} -i 2>/dev/null || netstat -tulpn 2>/dev/null | grep ${pid}`;
    }

    /**
     * Parse lsof/netstat output to extract listening ports.
     * 
     * lsof format:
     *   language_ 1234 user  10u  IPv4 0x... 0t0  TCP 127.0.0.1:2873 (LISTEN)
     * 
     * netstat format (Linux):
     *   tcp  0  0  127.0.0.1:2873  0.0.0.0:*  LISTEN  1234/language_server
     */
    parseListeningPorts(stdout: string): number[] {
        const ports: number[] = [];

        if (!stdout || stdout.trim().length === 0) {
            return ports;
        }

        const lines = stdout.trim().split('\n');

        for (const line of lines) {
            // Try lsof format first: look for 127.0.0.1:PORT (LISTEN)
            const lsofMatch = line.match(/127\.0\.0\.1:(\d+).*\(LISTEN\)/);
            if (lsofMatch && lsofMatch[1]) {
                const port = parseInt(lsofMatch[1], 10);
                if (!ports.includes(port)) {
                    ports.push(port);
                }
                continue;
            }

            // Try netstat format: 127.0.0.1:PORT ... LISTEN
            const netstatMatch = line.match(/127\.0\.0\.1:(\d+).*LISTEN/);
            if (netstatMatch && netstatMatch[1]) {
                const port = parseInt(netstatMatch[1], 10);
                if (!ports.includes(port)) {
                    ports.push(port);
                }
                continue;
            }

            // Also try localhost format
            const localhostMatch = line.match(/localhost:(\d+).*\(LISTEN\)|localhost:(\d+).*LISTEN/);
            if (localhostMatch) {
                const port = parseInt(localhostMatch[1] || localhostMatch[2], 10);
                if (!ports.includes(port)) {
                    ports.push(port);
                }
            }
        }

        return ports.sort((a, b) => a - b);
    }

    /**
     * Get Unix-specific error messages.
     */
    getErrorMessages(): {
        processNotFound: string;
        commandNotAvailable: string;
        requirements: string[];
    } {
        const processName = this.platform === 'darwin'
            ? 'language_server_macos'
            : 'language_server_linux';

        return {
            processNotFound: 'language_server process not found',
            commandNotAvailable: 'ps/lsof commands are unavailable; please check the system environment',
            requirements: [
                'Antigravity is running',
                `${processName} process is running`,
                'The system has permission to execute ps and lsof commands'
            ]
        };
    }
}
