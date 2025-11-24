/**
 * Status bar service
 */

import * as vscode from 'vscode';
import { ModelQuotaInfo, QuotaLevel, QuotaSnapshot } from './types';

export class StatusBarService {
  private statusBarItem: vscode.StatusBarItem;
  private warningThreshold: number;
  private criticalThreshold: number;
  private showPromptCredits: boolean;
  private displayStyle: 'percentage' | 'progressBar';

  constructor(
    warningThreshold: number = 50,
    criticalThreshold: number = 30,
    showPromptCredits: boolean = false,
    displayStyle: 'percentage' | 'progressBar' = 'progressBar'
  ) {
    this.statusBarItem = vscode.window.createStatusBarItem(
      vscode.StatusBarAlignment.Right,
      100
    );
    this.statusBarItem.command = 'antigravity-quota-watcher.showQuota';
    this.warningThreshold = warningThreshold;
    this.criticalThreshold = criticalThreshold;
    this.showPromptCredits = showPromptCredits;
    this.displayStyle = displayStyle;
  }

  updateDisplay(snapshot: QuotaSnapshot): void {
    const parts: string[] = [];

    if (this.showPromptCredits && snapshot.promptCredits) {
      const { available, monthly, remainingPercentage } = snapshot.promptCredits;
      const creditsPart = `💳 ${available}/${this.formatNumber(monthly)} (${remainingPercentage.toFixed(0)}%)`;
      parts.push(creditsPart);
    }

    const modelsToShow = this.selectModelsToDisplay(snapshot.models);

    for (const model of modelsToShow) {
      const emoji = this.getModelEmoji(model.label);
      const shortName = this.getShortModelName(model.label);

      if (model.isExhausted) {
        if (this.displayStyle === 'progressBar') {
          parts.push(`${emoji} ${shortName} ${this.getProgressBar(0)}`);
        } else {
          parts.push(`${emoji} ${shortName}: 0%`);
        }
      } else if (model.remainingPercentage !== undefined) {
        if (this.displayStyle === 'progressBar') {
          parts.push(`${emoji} ${shortName} ${this.getProgressBar(model.remainingPercentage)}`);
        } else {
          parts.push(`${emoji} ${shortName}: ${model.remainingPercentage.toFixed(0)}%`);
        }
      }
    }

    if (parts.length === 0) {
      this.statusBarItem.text = '$(warning) Antigravity: Unable to fetch quota';
      this.statusBarItem.backgroundColor = undefined;
      this.statusBarItem.tooltip = 'Cannot connect to Antigravity Language Server';
    } else {
      const displayText = parts.join(' | ');
      this.statusBarItem.text = displayText;
      this.updateColor(snapshot);
      this.updateTooltip(snapshot);
    }

    this.statusBarItem.show();
  }

  private updateColor(snapshot: QuotaSnapshot): void {
    const level = this.getQuotaLevel(snapshot);

    switch (level) {
      case QuotaLevel.Normal:
        // 绿色：额度充足（≥50%）
        this.statusBarItem.backgroundColor = new vscode.ThemeColor('charts.green');
        break;
      case QuotaLevel.Warning:
        // 橙色：额度中等（30%-50%）
        this.statusBarItem.backgroundColor = new vscode.ThemeColor('charts.orange');
        break;
      case QuotaLevel.Critical:
      case QuotaLevel.Depleted:
        // 红色：额度不足（<30%）或已耗尽
        this.statusBarItem.backgroundColor = new vscode.ThemeColor('charts.red');
        break;
    }
  }

  private getQuotaLevel(snapshot: QuotaSnapshot): QuotaLevel {
    const creditsPercent = this.showPromptCredits
      ? snapshot.promptCredits?.remainingPercentage ?? 100
      : 100;

    const modelPercentages = snapshot.models
      .map(m => m.remainingPercentage ?? 0);

    const minPercentage = Math.min(creditsPercent, ...modelPercentages);

    // 三级阈值系统
    // Normal: > warningThreshold (默认50%)
    // Warning: criticalThreshold < percentage <= warningThreshold (默认30%-50%)
    // Critical: 0 < percentage <= criticalThreshold (默认<30%)
    // Depleted: percentage <= 0

    if (minPercentage <= 0) {
      return QuotaLevel.Depleted;
    } else if (minPercentage <= this.criticalThreshold) {
      return QuotaLevel.Critical;
    } else if (minPercentage <= this.warningThreshold) {
      return QuotaLevel.Warning;
    }
    return QuotaLevel.Normal;
  }

  setWarningThreshold(threshold: number): void {
    this.warningThreshold = threshold;
  }

  setCriticalThreshold(threshold: number): void {
    this.criticalThreshold = threshold;
  }

  setShowPromptCredits(value: boolean): void {
    this.showPromptCredits = value;
  }

  setDisplayStyle(value: 'percentage' | 'progressBar'): void {
    this.displayStyle = value;
  }

  private updateTooltip(snapshot: QuotaSnapshot): void {
    const lines: string[] = ['Antigravity Quota Status', ''];

    if (this.showPromptCredits && snapshot.promptCredits) {
      lines.push('💳 Prompt Credits');
      lines.push(`  Available: ${snapshot.promptCredits.available} / ${snapshot.promptCredits.monthly}`);
      lines.push(`  Remaining: ${snapshot.promptCredits.remainingPercentage.toFixed(1)}%`);
      lines.push('');
    }

    for (const model of snapshot.models) {
      const emoji = this.getModelEmoji(model.label);
      lines.push(`${emoji} ${model.label}`);

      if (model.isExhausted) {
        lines.push('  ⚠️ Quota depleted');
      } else if (model.remainingPercentage !== undefined) {
        lines.push(`  Remaining: ${model.remainingPercentage.toFixed(1)}%`);
      }

      lines.push(`  Reset in ${model.timeUntilResetFormatted}`);
      lines.push('');
    }

    this.statusBarItem.tooltip = lines.join('\n');
  }

  private selectModelsToDisplay(models: ModelQuotaInfo[]): ModelQuotaInfo[] {
    const result: ModelQuotaInfo[] = [];

    const proLow = models.find(model => this.isProLow(model.label));
    if (proLow) {
      result.push(proLow);
    }

    const claude = models.find(model => this.isClaudeWithoutThinking(model.label));
    if (claude && claude !== proLow) {
      result.push(claude);
    }

    for (const model of models) {
      if (result.length >= 2) break;
      if (!result.includes(model)) {
        result.push(model);
      }
    }

    return result.slice(0, 2);
  }

  private isProLow(label: string): boolean {
    const lower = label.toLowerCase();
    return lower.includes('pro') && lower.includes('low');
  }

  private isClaudeWithoutThinking(label: string): boolean {
    const lower = label.toLowerCase();
    return lower.includes('claude') && !lower.includes('thinking');
  }

  private formatNumber(num: number): string {
    if (num >= 1000) {
      return `${(num / 1000).toFixed(0)}k`;
    }
    return num.toString();
  }

  private getModelEmoji(label: string): string {
    if (label.includes('Claude')) {
      return '🤖';
    }
    if (label.includes('Gemini') && label.includes('Flash')) {
      return '⚡';
    }
    if (label.includes('Gemini') && label.includes('Pro')) {
      return '💎';
    }
    if (label.includes('GPT')) {
      return '🔮';
    }
    return '📊';
  }

  private getShortModelName(label: string): string {
    if (label.includes('Claude')) {
      return 'Claude';
    }
    if (label.includes('Flash')) {
      return 'Flash';
    }
    if (label.includes('Pro (High)')) {
      return 'Pro-H';
    }
    if (label.includes('Pro (Low)')) {
      return 'Pro-L';
    }
    if (label.includes('Pro')) {
      return 'Pro';
    }
    if (label.includes('GPT')) {
      return 'GPT';
    }

    return label.split(' ')[0];
  }

  private getProgressBar(percentage: number, width: number = 8): string {
    // 确保百分比在 0-100 之间
    const p = Math.max(0, Math.min(100, percentage));
    // 计算填充的块数
    const filledCount = Math.round((p / 100) * width);
    const emptyCount = width - filledCount;

    const filled = '█'.repeat(filledCount);
    const empty = '░'.repeat(emptyCount);

    return `${filled}${empty}`;
  }

  showError(message: string): void {
    this.statusBarItem.text = '$(error) Antigravity Quota Watcher: Error';
    this.statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
    this.statusBarItem.tooltip = message;
    this.statusBarItem.show();
  }

  clearError(): void {
    this.statusBarItem.text = '$(sync~spin) Antigravity Quota Watcher: Loading...';
    this.statusBarItem.backgroundColor = undefined;
    this.statusBarItem.tooltip = 'Fetching quota information...';
    this.statusBarItem.show();
  }

  show(): void {
    this.statusBarItem.show();
  }

  hide(): void {
    this.statusBarItem.hide();
  }

  dispose(): void {
    this.statusBarItem.dispose();
  }
}
