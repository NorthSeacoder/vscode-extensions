// This file is generated by `vscode-ext-gen`. Do not modify manually.
// @see https://github.com/antfu/vscode-ext-gen

// Meta info
export const publisher = "NorthSeacoder"
export const name = "jump"
export const version = "1.0.1"
export const displayName = "Jump"
export const description = undefined
export const extensionId = `${publisher}.${name}`

/**
 * Type union of all commands
 */
export type CommandKey = 
  | "jump"

/**
 * Commands map registed by `NorthSeacoder.jump`
 */
export const commands = {
  /**
   * Jump
   * @value `jump`
   */
  jump: "jump",
} satisfies Record<string, CommandKey>

/**
 * Type union of all configs
 */
export type ConfigKey = 
  | "jump.url"
  | "jump.label"

export interface ConfigKeyTypeMap {
  "jump.url": string,
  "jump.label": string,
}

export interface ConfigShorthandMap {
  url: "jump.url",
  label: "jump.label",
}

export interface ConfigItem<T extends keyof ConfigKeyTypeMap> {
  key: T,
  default: ConfigKeyTypeMap[T],
}


/**
 * Configs map registed by `NorthSeacoder.jump`
 */
export const configs = {
  /**
   * any url you want to jump
   * @key `jump.url`
   * @default `"https://code.visualstudio.com/"`
   * @type `string`
   */
  url: {
    key: "jump.url",
    default: "https://code.visualstudio.com/",
  } as ConfigItem<"jump.url">,
  /**
   * the label show in the status bar
   * @key `jump.label`
   * @default `"code"`
   * @type `string`
   */
  label: {
    key: "jump.label",
    default: "code",
  } as ConfigItem<"jump.label">,
}

export interface ScopedConfigKeyTypeMap {
  "url": string,
  "label": string,
}

export const scopedConfigs = {
  scope: "jump",
  defaults: {
    "url": "https://code.visualstudio.com/",
    "label": "code",
  } satisfies ScopedConfigKeyTypeMap,
}

