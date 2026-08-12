/**
 * Browser automation tool — fills web forms using vault credentials via Playwright.
 * Secrets are injected directly into the browser, never returned in tool output.
 */

import { chromium, type Browser, type Page } from 'playwright';
import type { Resolver } from './inject.js';

export interface BrowserFillOptions {
  /** CSS selector → vault ref (supports "Item:field" syntax). Filled in order. */
  fields: Record<string, string>;
  /** CSS selector to click after all fields are filled (form submit button etc.). */
  submitSelector?: string;
  /** Wait for this selector to appear after submit — confirms the action succeeded. */
  waitForSelector?: string;
  /** Extract and return the text content of this selector after the action. */
  extractSelector?: string;
  /** Return a base64 PNG screenshot after the action. Default: false. */
  screenshot?: boolean;
  /** Run in headless mode. Default: true. */
  headless?: boolean;
  /** Navigation + action timeout in ms. Default: 30000. */
  timeout?: number;
  /** Extra HTTP headers (e.g. {"Accept-Language": "de-DE"}). */
  extraHeaders?: Record<string, string>;
}

export interface BrowserFillResult {
  success: boolean;
  finalUrl: string;
  pageTitle: string;
  /** Text content of extractSelector (if provided). */
  extractedContent?: string;
  /** Base64 PNG screenshot (if screenshot=true or on error). */
  screenshot?: string;
  error?: string;
}

export async function browserFillForm(
  resolver: Resolver,
  url: string,
  options: BrowserFillOptions,
): Promise<BrowserFillResult> {
  const timeout = options.timeout ?? 30_000;
  const headless = options.headless !== false;

  // Resolve all vault refs up-front (secrets never touch return value)
  const resolvedFields = new Map<string, string>();
  await Promise.all(
    Object.entries(options.fields).map(async ([selector, ref]) => {
      resolvedFields.set(selector, await resolver(ref));
    }),
  );

  const browser: Browser = await chromium.launch({ headless });
  const context = await browser.newContext({
    extraHTTPHeaders: options.extraHeaders ?? {},
  });
  const page: Page = await context.newPage();

  try {
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout });

    // Fill each field in the declared order
    for (const [selector, value] of resolvedFields) {
      const el = page.locator(selector).first();
      await el.waitFor({ state: 'visible', timeout });

      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const tag = await el.evaluate((n: any) => n.tagName.toLowerCase());
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const inputType = await el.evaluate((n: any) => n.type?.toLowerCase() ?? '');

      if (tag === 'select') {
        await el.selectOption(value);
      } else if (inputType === 'checkbox' || inputType === 'radio') {
        const checked = value.toLowerCase() === 'true' || value === '1';
        if (checked) await el.check(); else await el.uncheck();
      } else {
        // Clear existing value before typing
        await el.fill(value);
      }
    }

    if (options.submitSelector) {
      await page.locator(options.submitSelector).first().click({ timeout });
    }

    if (options.waitForSelector) {
      await page.waitForSelector(options.waitForSelector, { timeout });
    }

    const finalUrl = page.url();
    const pageTitle = await page.title();

    let extractedContent: string | undefined;
    if (options.extractSelector) {
      const el = page.locator(options.extractSelector).first();
      await el.waitFor({ state: 'visible', timeout }).catch(() => { /* may not appear */ });
      extractedContent = await el.textContent() ?? undefined;
    }

    let screenshot: string | undefined;
    if (options.screenshot) {
      screenshot = (await page.screenshot({ type: 'png' })).toString('base64');
    }

    await context.close();
    await browser.close();
    return { success: true, finalUrl, pageTitle, extractedContent, screenshot };

  } catch (err) {
    const errorMsg = err instanceof Error ? err.message : String(err);

    let screenshot: string | undefined;
    try {
      screenshot = (await page.screenshot({ type: 'png' })).toString('base64');
    } catch { /* ignore */ }

    await context.close().catch(() => { /* ignore */ });
    await browser.close().catch(() => { /* ignore */ });

    return {
      success: false,
      finalUrl: page.url(),
      pageTitle: await page.title().catch(() => ''),
      screenshot,
      error: errorMsg,
    };
  }
}
