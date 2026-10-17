type PendingSave = {
  contentHash: string;
  expiresAt: number;
};

export class OneShotSaveWatcherSuppression {
  private readonly pending = new Map<string, PendingSave>();

  constructor(
    private readonly ttlMs: number = 2_000,
    private readonly now: () => number = () => Date.now()
  ) {
    if (!Number.isFinite(ttlMs) || ttlMs <= 0) {
      throw new Error("ttlMs must be a positive finite number");
    }
  }

  mark(absolutePath: string, contentHash: string): void {
    const currentTime = this.now();
    this.purgeExpired(currentTime);

    this.pending.set(absolutePath, {
      contentHash,
      expiresAt: currentTime + this.ttlMs,
    });
  }

  consume(absolutePath: string, contentHash: string): boolean {
    const currentTime = this.now();
    this.purgeExpired(currentTime);

    const pendingSave = this.pending.get(absolutePath);

    if (!pendingSave) {
      return false;
    }

    this.pending.delete(absolutePath);

    return (
      pendingSave.expiresAt >= currentTime &&
      pendingSave.contentHash === contentHash
    );
  }

  clear(absolutePath: string, contentHash: string): void {
    const pendingSave = this.pending.get(absolutePath);

    if (pendingSave?.contentHash === contentHash) {
      this.pending.delete(absolutePath);
    }
  }

  private purgeExpired(currentTime: number): void {
    for (const [absolutePath, pendingSave] of this.pending) {
      if (pendingSave.expiresAt < currentTime) {
        this.pending.delete(absolutePath);
      }
    }
  }
}

const defaultSuppression = new OneShotSaveWatcherSuppression();

export function markEditorSaveWatcherEvent(
  absolutePath: string,
  contentHash: string
): void {
  defaultSuppression.mark(absolutePath, contentHash);
}

export function consumeEditorSaveWatcherEvent(
  absolutePath: string,
  contentHash: string
): boolean {
  return defaultSuppression.consume(absolutePath, contentHash);
}

export function clearEditorSaveWatcherEvent(
  absolutePath: string,
  contentHash: string
): void {
  defaultSuppression.clear(absolutePath, contentHash);
}
