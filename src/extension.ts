/**
 * Antigravity Quota Watcher - main extension file
 */

import * as vscode from 'vscode';
import { QuotaService, QuotaApiMethod } from './quotaService';
import { StatusBarService } from './statusBar';
import { ConfigService } from './configService';
import { PortDetectionService, PortDetectionResult } from './portDetectionService';
import { Config, QuotaSnapshot } from './types';

let quotaService: QuotaService | undefined;
let statusBarService: StatusBarService | undefined;
let configService: ConfigService | undefined;
let portDetectionService: PortDetectionService | undefined;

/**
 * Called when the extension is activated
 */
export async function activate(context: vscode.ExtensionContext) {
  console.log('Antigravity Quota Watcher activated');

  // Init services
  configService = new ConfigService();
  let config = configService.getConfig();

  portDetectionService = new PortDetectionService(context);

  // Auto detect port and csrf token
  let detectedPort: number | null = null;
  let detectedCsrfToken: string | null = null;
  let detectionResult: PortDetectionResult | null = null;

  try {
    const result = await portDetectionService.detectPort();
    if (result) {
      detectionResult = result;
      detectedPort = result.port;
      detectedCsrfToken = result.csrfToken;
    }
  } catch (error) {
    console.error('Port/CSRF detection failed', error);
  }

  // Init status bar
  statusBarService = new StatusBarService(
    config.warningThreshold,
    config.criticalThreshold,
    config.showPromptCredits,
    config.displayStyle
  );

  // Ensure port and CSRF token are available
  if (!detectedPort || !detectedCsrfToken) {
    console.error('Missing port or CSRF Token, extension cannot start');
    console.error('Please ensure language_server_windows_x64.exe is running');
    statusBarService.showError('检测失败');
    statusBarService.show();

    // 显示用户提示,提供重试选项
    vscode.window.showWarningMessage(
      'Antigravity Quota Watcher: 无法检测到 Antigravity 进程。请确保 Antigravity 正在运行。',
      '重试',
      '取消'
    ).then(action => {
      if (action === '重试') {
        vscode.commands.executeCommand('antigravity-quota-watcher.detectPort');
      }
    });
  } else {
    // Init quota service
    quotaService = new QuotaService(detectedPort, undefined, detectionResult?.httpPort);
    // Set ports for HTTPS + HTTP fallback
    quotaService.setPorts(detectionResult?.connectPort ?? detectedPort, detectionResult?.httpPort);
    // Choose endpoint based on config
    quotaService.setApiMethod(config.apiMethod === 'COMMAND_MODEL_CONFIG'
      ? QuotaApiMethod.COMMAND_MODEL_CONFIG
      : QuotaApiMethod.GET_USER_STATUS);

    // Register quota update callback
    quotaService.onQuotaUpdate((snapshot: QuotaSnapshot) => {
      statusBarService?.updateDisplay(snapshot);
    });

    // Register error callback (silent, only update status bar)
    quotaService.onError((error: Error) => {
      console.error('Quota fetch failed:', error);
      statusBarService?.showError(`Connection failed: ${error.message}`);
    });

    // If enabled, start polling after a short delay
    if (config.enabled) {
      console.log('Starting quota polling after delay...');

      setTimeout(() => {
        quotaService?.setAuthInfo(undefined, detectedCsrfToken);
        quotaService?.startPolling(config.pollingInterval);
      }, 6000);

      statusBarService.show();
    }
  }

  // Command: show quota details (placeholder)
  const showQuotaCommand = vscode.commands.registerCommand(
    'antigravity-quota-watcher.showQuota',
    () => {
      // TODO: implement quota detail panel
    }
  );

  // Command: refresh quota
  const refreshQuotaCommand = vscode.commands.registerCommand(
    'antigravity-quota-watcher.refreshQuota',
    async () => {
      vscode.window.showInformationMessage('Refreshing quota...');
      config = configService!.getConfig();
      statusBarService?.setWarningThreshold(config.warningThreshold);
      statusBarService?.setCriticalThreshold(config.criticalThreshold);
      statusBarService?.setShowPromptCredits(config.showPromptCredits);
      statusBarService?.setDisplayStyle(config.displayStyle);
      if (config.enabled && quotaService) {
        quotaService.stopPolling();
        quotaService.setApiMethod(config.apiMethod === 'COMMAND_MODEL_CONFIG'
          ? QuotaApiMethod.COMMAND_MODEL_CONFIG
          : QuotaApiMethod.GET_USER_STATUS);
        quotaService.startPolling(config.pollingInterval);
      }
    }
  );

  // Command: re-detect port
  const detectPortCommand = vscode.commands.registerCommand(
    'antigravity-quota-watcher.detectPort',
    async () => {
      vscode.window.showInformationMessage('🔍 正在重新检测端口...');

      config = configService!.getConfig();
      statusBarService?.setWarningThreshold(config.warningThreshold);
      statusBarService?.setCriticalThreshold(config.criticalThreshold);
      statusBarService?.setShowPromptCredits(config.showPromptCredits);
      statusBarService?.setDisplayStyle(config.displayStyle);

      try {
        const result = await portDetectionService?.detectPort();

        if (result && result.port && result.csrfToken) {
          // 如果之前没有 quotaService,需要初始化
          if (!quotaService) {
            quotaService = new QuotaService(result.port, result.csrfToken, result.httpPort);
            quotaService.setPorts(result.connectPort, result.httpPort);

            // 注册回调
            quotaService.onQuotaUpdate((snapshot: QuotaSnapshot) => {
              statusBarService?.updateDisplay(snapshot);
            });

            quotaService.onError((error: Error) => {
              console.error('Quota fetch failed:', error);
              statusBarService?.showError(`Connection failed: ${error.message}`);
            });
          } else {
            // 更新现有服务的端口
            quotaService.setPorts(result.connectPort, result.httpPort);
            quotaService.setAuthInfo(undefined, result.csrfToken);
          }

          // 清除之前的错误状态
          statusBarService?.clearError();

          quotaService.stopPolling();
          quotaService.setApiMethod(config.apiMethod === 'COMMAND_MODEL_CONFIG'
            ? QuotaApiMethod.COMMAND_MODEL_CONFIG
            : QuotaApiMethod.GET_USER_STATUS);
          quotaService.startPolling(config.pollingInterval);

          vscode.window.showInformationMessage(`✅ 检测成功! 端口: ${result.port}`);
        } else {
          vscode.window.showErrorMessage(
            '❌ 无法检测到有效端口。请确保:\n' +
            '1. Antigravity 正在运行\n' +
            '2. language_server_windows_x64.exe 进程存在\n' +
            '3. 系统有足够权限执行检测命令'
          );
        }
      } catch (error: any) {
        const errorMsg = error?.message || String(error);
        console.error('端口检测失败:', errorMsg);
        vscode.window.showErrorMessage(`❌ 端口检测失败: ${errorMsg}`);
      }
    }
  );

  // Listen to config changes
  const configChangeDisposable = configService.onConfigChange((newConfig) => {
    handleConfigChange(newConfig as Config);
  });

  // Add to context subscriptions
  context.subscriptions.push(
    showQuotaCommand,
    refreshQuotaCommand,
    detectPortCommand,
    configChangeDisposable,
    { dispose: () => quotaService?.dispose() },
    { dispose: () => statusBarService?.dispose() }
  );

  // Startup log
  console.log('Antigravity Quota Watcher initialized');
}

/**
 * Handle config changes
 */
function handleConfigChange(config: Config): void {
  console.log('Config updated', config);

  quotaService?.setApiMethod(config.apiMethod === 'COMMAND_MODEL_CONFIG'
    ? QuotaApiMethod.COMMAND_MODEL_CONFIG
    : QuotaApiMethod.GET_USER_STATUS);
  statusBarService?.setWarningThreshold(config.warningThreshold);
  statusBarService?.setCriticalThreshold(config.criticalThreshold);
  statusBarService?.setShowPromptCredits(config.showPromptCredits);
  statusBarService?.setDisplayStyle(config.displayStyle);

  if (config.enabled) {
    quotaService?.startPolling(config.pollingInterval);
    statusBarService?.show();
  } else {
    quotaService?.stopPolling();
    statusBarService?.hide();
  }

  vscode.window.showInformationMessage('Antigravity Quota Watcher config updated');
}

/**
 * Called when the extension is deactivated
 */
export function deactivate() {
  console.log('Antigravity Quota Watcher deactivated');
  quotaService?.dispose();
  statusBarService?.dispose();
}
