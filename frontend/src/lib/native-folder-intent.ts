/** A one-shot signal set immediately before triggering the native folder
 * picker (window.marcellusNativeWorkspace.selectFolder()) and consumed once
 * by the marcellus:native-workspace-selected listener when the picker
 * resolves. The native picker round trip only ever returns {token, name} --
 * Swift's grantWorkspace has no way to carry an extra flag through it -- so
 * this in-memory signal is how "New Project" (Sidebar) tells the listener
 * (AIWorkspace) to always create a brand-new project instead of guessing at
 * a name match against an existing one. Module-scoped rather than exported
 * state on window: both call sites run in the same page, and the intent is
 * only ever relevant to the very next folder-picker resolution.
 */
let forceNewProjectOnNextPick = false;

export function markNextFolderPickAsNewProject(): void {
  forceNewProjectOnNextPick = true;
}

/** Consumes (reads and clears) the pending intent. Always clears so a stray
 * or cancelled picker invocation can never leave a stale flag armed for an
 * unrelated later pick. */
export function consumeForceNewProjectIntent(): boolean {
  const value = forceNewProjectOnNextPick;
  forceNewProjectOnNextPick = false;
  return value;
}
