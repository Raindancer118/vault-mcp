export interface VaultInstanceConfig {
  url: string;
  clientId: string;
  clientSecret: string;
  /** Plaintext master password — use masterPasswordCmd or masterPasswordPrompt instead */
  masterPassword?: string;
  /** Shell command whose stdout is the master password */
  masterPasswordCmd?: string;
  /**
   * If true, prompt the user for the master password via a GUI dialog (zenity/kdialog/browser form).
   * The password is held in RAM only and never written to disk.
   */
  masterPasswordPrompt?: boolean;
  email: string;
  description?: string;
}

export interface Config {
  version: 1;
  /** Hex-encoded 32 random bytes — used for project vault key derivation */
  masterKey: string;
  defaultVault?: string;
  vaults: Record<string, VaultInstanceConfig>;
}
