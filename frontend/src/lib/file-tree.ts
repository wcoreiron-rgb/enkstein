import type { CortexArtifact } from '@/lib/api';

export type FileTreeNode =
  | { kind: 'folder'; name: string; path: string; children: FileTreeNode[] }
  | { kind: 'file'; name: string; path: string; artifact: CortexArtifact };

/** Groups a flat, project-scoped artifact list into a nested VS Code-style
 * folder tree. Purely presentational and derived fresh from `artifacts` on
 * every render (no separate state to fall out of sync with the active
 * project's real file list). Folders are sorted before files, both
 * alphabetically, at every level. */
export function buildFileTree(artifacts: CortexArtifact[]): FileTreeNode[] {
  const root: FileTreeNode[] = [];

  for (const artifact of artifacts) {
    const segments = artifact.path.split('/').filter(Boolean);
    if (!segments.length) continue;
    let level = root;
    let accumulatedPath = '';
    for (let index = 0; index < segments.length - 1; index += 1) {
      const segment = segments[index];
      accumulatedPath = accumulatedPath ? `${accumulatedPath}/${segment}` : segment;
      let folder = level.find((node): node is Extract<FileTreeNode, { kind: 'folder' }> => node.kind === 'folder' && node.name === segment);
      if (!folder) {
        folder = { kind: 'folder', name: segment, path: accumulatedPath, children: [] };
        level.push(folder);
      }
      level = folder.children;
    }
    const fileName = segments[segments.length - 1];
    level.push({ kind: 'file', name: fileName, path: artifact.path, artifact });
  }

  const sortTree = (nodes: FileTreeNode[]): FileTreeNode[] => {
    const sorted = [...nodes].sort((a, b) => {
      if (a.kind !== b.kind) return a.kind === 'folder' ? -1 : 1;
      return a.name.localeCompare(b.name, undefined, { sensitivity: 'base' });
    });
    for (const node of sorted) {
      if (node.kind === 'folder') node.children = sortTree(node.children);
    }
    return sorted;
  };

  return sortTree(root);
}

/** Every folder path present in the tree, used to default-expand a project
 * with a small/moderate number of folders so the tree isn't collapsed by
 * default the first time a project's files are shown. */
export function allFolderPaths(nodes: FileTreeNode[]): string[] {
  const paths: string[] = [];
  const walk = (level: FileTreeNode[]) => {
    for (const node of level) {
      if (node.kind === 'folder') {
        paths.push(node.path);
        walk(node.children);
      }
    }
  };
  walk(nodes);
  return paths;
}
