/**
 * Safe PowerShell path resolver.
 * Implements a controlled search order to prevent path hijacking attacks.
 * 
 * Security concern: When using just 'powershell' without an absolute path,
 * the OS searches according to the PATH environment variable order.
 * This creates a risk where the current working directory (e.g., a malicious
 * repository opened in VS Code) could contain a fake powershell.exe.
 * 
 * Solution: We implement our own search logic with trusted paths only.
 * 
 * Search order:
 * 1. System32 legacy PowerShell (most stable, admin-protected)
 * 2. Known PowerShell 7/6 installation paths (Program Files, admin-protected)
 * 3. PATH environment variable (only as last resort)
 */

import * as fs from 'fs';
import * as path from 'path';

export class SafePowerShellPath {
    private static readonly SYSTEM_ROOT: string = process.env.SystemRoot || 'C:\\Windows';

    // Known safe paths - these directories require admin privileges to modify
    private static readonly KNOWN_SAFE_PATHS: readonly string[] = [
        // Priority 1: System32 legacy PowerShell (most reliable fallback)
        path.join(SafePowerShellPath.SYSTEM_ROOT, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe'),

        // Priority 2: PowerShell 7+ in Program Files (admin-protected directories)
        'C:\\Program Files\\PowerShell\\7\\pwsh.exe',
        path.join(SafePowerShellPath.SYSTEM_ROOT, 'System32', 'pwsh.exe'), // If pwsh is in System32
        'C:\\Program Files\\PowerShell\\6\\pwsh.exe',
        'C:\\Program Files (x86)\\PowerShell\\7\\pwsh.exe',
        'C:\\Program Files (x86)\\PowerShell\\6\\pwsh.exe',
    ] as const;

    private static cachedPath: string | null = null;
    private static pathType: 'system32' | 'pwsh7' | 'path_fallback' | 'not_found' = 'not_found';

    /**
     * Get the safe PowerShell executable path.
     * Uses controlled search order to prevent path hijacking.
     * Result is cached for performance.
     * 
     * @returns The path to PowerShell executable (with quotes for safe execution)
     * @throws Error if PowerShell cannot be found in any trusted location
     */
    public static getSafePath(): string {
        if (this.cachedPath !== null) {
            return this.cachedPath;
        }

        const result = this.findSafePath();
        this.cachedPath = result.path;
        this.pathType = result.type;

        console.log(`[SafePowerShellPath] Using PowerShell from: ${result.path} (type: ${result.type})`);

        return this.cachedPath;
    }

    /**
     * Get information about the currently resolved PowerShell path.
     */
    public static getPathInfo(): { path: string; type: 'system32' | 'pwsh7' | 'path_fallback' | 'not_found' } {
        if (this.cachedPath === null) {
            this.getSafePath();
        }
        return { path: this.cachedPath || '', type: this.pathType };
    }

    /**
     * Clear the cached path. Useful for testing or when configuration changes.
     */
    public static clearCache(): void {
        this.cachedPath = null;
        this.pathType = 'not_found';
    }

    /**
     * Find PowerShell executable using controlled search order.
     */
    private static findSafePath(): { path: string; type: 'system32' | 'pwsh7' | 'path_fallback' | 'not_found' } {
        // Step 1 & 2: Check known safe paths in order
        for (let i = 0; i < this.KNOWN_SAFE_PATHS.length; i++) {
            const safePath = this.KNOWN_SAFE_PATHS[i];
            try {
                if (fs.existsSync(safePath)) {
                    // Determine type based on path
                    const type = i === 0 ? 'system32' : 'pwsh7';
                    // Return with quotes to handle spaces in path
                    return { path: `"${safePath}"`, type };
                }
            } catch (e) {
                // Ignore access errors and continue searching
                console.log(`[SafePowerShellPath] Cannot access ${safePath}: ${e}`);
            }
        }

        // Step 3: Fallback to PATH (least preferred)
        // Note: This is less secure but necessary for compatibility with
        // non-standard Windows installations (e.g., Windows Server Core,
        // custom PowerShell installations, etc.)
        console.log('[SafePowerShellPath] Warning: No PowerShell found in trusted paths, falling back to PATH lookup');

        // We return just 'powershell' here, but the caller (WindowsProcessDetector)
        // should ensure the spawn options don't allow CWD hijacking
        return { path: 'powershell', type: 'path_fallback' };
    }

    /**
     * Check if the current PowerShell path is using the PATH fallback.
     * This is useful for logging warnings about potential security concerns.
     */
    public static isUsingPathFallback(): boolean {
        this.getSafePath(); // Ensure path is resolved
        return this.pathType === 'path_fallback';
    }

    /**
     * Get all available PowerShell installations on the system.
     * Useful for debugging and user feedback.
     */
    public static getAvailableInstallations(): string[] {
        const available: string[] = [];

        for (const safePath of this.KNOWN_SAFE_PATHS) {
            try {
                if (fs.existsSync(safePath)) {
                    available.push(safePath);
                }
            } catch (e) {
                // Ignore access errors
            }
        }

        return available;
    }
}
