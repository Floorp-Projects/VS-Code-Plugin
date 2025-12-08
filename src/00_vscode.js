// VSCode Plugin JavaScript Bindings
// SPDX-FileCopyrightText: 2025 Yuta Takahashi
// SPDX-License-Identifier: MPL-2.0 OR GPL-3.0-or-later

const vscode = {
    open_folder: (path) => Deno.core.ops.op2_vscode_open_folder(path),
    open_file: (path) => Deno.core.ops.op2_vscode_open_file(path),
    write_file: (path, content) => Deno.core.ops.op2_vscode_write_file(path, content),
    close_workspace: () => Deno.core.ops.op2_vscode_close_workspace(),
};
