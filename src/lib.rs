// VSCode Plugin for Sapphillon
// SPDX-FileCopyrightText: 2025 Yuta Takahashi
// SPDX-License-Identifier: MPL-2.0 OR GPL-3.0-or-later

use deno_core::{OpState, op2};
use deno_error::JsErrorBox;
use sapphillon_core::permission::{
    CheckPermissionResult, PluginFunctionPermissions, check_permission,
};
use sapphillon_core::plugin::{CorePluginFunction, CorePluginPackage};
use sapphillon_core::proto::sapphillon::v1::{
    Permission, PermissionLevel, PermissionType, PluginFunction, PluginPackage,
};
use sapphillon_core::runtime::OpStateWorkflowData;
use std::process::Command;
use std::sync::{Arc, Mutex};

// ============================================================================
// Plugin Function Definitions
// ============================================================================

pub fn vscode_open_folder_plugin_function() -> PluginFunction {
    PluginFunction {
        function_id: "app.sapphillon.core.vscode.open_folder".to_string(),
        function_name: "vscode.open_folder".to_string(),
        description: "Opens a folder in VSCode.".to_string(),
        permissions: vscode_plugin_permissions(),
        arguments: "String: path".to_string(),
        returns: "String: result".to_string(),
    }
}

pub fn vscode_open_file_plugin_function() -> PluginFunction {
    PluginFunction {
        function_id: "app.sapphillon.core.vscode.open_file".to_string(),
        function_name: "vscode.open_file".to_string(),
        description: "Opens a file in VSCode.".to_string(),
        permissions: vscode_plugin_permissions(),
        arguments: "String: path".to_string(),
        returns: "String: result".to_string(),
    }
}

pub fn vscode_write_file_plugin_function() -> PluginFunction {
    PluginFunction {
        function_id: "app.sapphillon.core.vscode.write_file".to_string(),
        function_name: "vscode.write_file".to_string(),
        description: "Writes content to a file and opens it in VSCode.".to_string(),
        permissions: vscode_write_plugin_permissions(),
        arguments: "String: path, String: content".to_string(),
        returns: "String: result".to_string(),
    }
}

pub fn vscode_close_workspace_plugin_function() -> PluginFunction {
    PluginFunction {
        function_id: "app.sapphillon.core.vscode.close_workspace".to_string(),
        function_name: "vscode.close_workspace".to_string(),
        description: "Closes the current VSCode workspace/project.".to_string(),
        permissions: vscode_plugin_permissions(),
        arguments: "".to_string(),
        returns: "String: result".to_string(),
    }
}

pub fn vscode_plugin_package() -> PluginPackage {
    PluginPackage {
        package_id: "app.sapphillon.core.vscode".to_string(),
        package_name: "VSCode".to_string(),
        description: "A plugin to manage VSCode (Visual Studio Code).".to_string(),
        functions: vec![
            vscode_open_folder_plugin_function(),
            vscode_open_file_plugin_function(),
            vscode_write_file_plugin_function(),
            vscode_close_workspace_plugin_function(),
        ],
        package_version: env!("CARGO_PKG_VERSION").to_string(),
        deprecated: None,
        plugin_store_url: "BUILTIN".to_string(),
        internal_plugin: Some(true),
        installed_at: None,
        updated_at: None,
        verified: Some(true),
    }
}

// ============================================================================
// Core Plugin Functions (for Deno runtime integration)
// ============================================================================

pub fn core_vscode_open_folder_plugin() -> CorePluginFunction {
    CorePluginFunction::new(
        "app.sapphillon.core.vscode.open_folder".to_string(),
        "vscode.open_folder".to_string(),
        "Opens a folder in VSCode.".to_string(),
        op2_vscode_open_folder(),
        Some(include_str!("00_vscode.js").to_string()),
    )
}

pub fn core_vscode_open_file_plugin() -> CorePluginFunction {
    CorePluginFunction::new(
        "app.sapphillon.core.vscode.open_file".to_string(),
        "vscode.open_file".to_string(),
        "Opens a file in VSCode.".to_string(),
        op2_vscode_open_file(),
        None,
    )
}

pub fn core_vscode_write_file_plugin() -> CorePluginFunction {
    CorePluginFunction::new(
        "app.sapphillon.core.vscode.write_file".to_string(),
        "vscode.write_file".to_string(),
        "Writes content to a file and opens it in VSCode.".to_string(),
        op2_vscode_write_file(),
        None,
    )
}

pub fn core_vscode_close_workspace_plugin() -> CorePluginFunction {
    CorePluginFunction::new(
        "app.sapphillon.core.vscode.close_workspace".to_string(),
        "vscode.close_workspace".to_string(),
        "Closes the current VSCode workspace/project.".to_string(),
        op2_vscode_close_workspace(),
        None,
    )
}

pub fn core_vscode_plugin_package() -> CorePluginPackage {
    CorePluginPackage::new(
        "app.sapphillon.core.vscode".to_string(),
        "VSCode".to_string(),
        vec![
            core_vscode_open_folder_plugin(),
            core_vscode_open_file_plugin(),
            core_vscode_write_file_plugin(),
            core_vscode_close_workspace_plugin(),
        ],
    )
}

// ============================================================================
// Permission Definitions
// ============================================================================

fn vscode_plugin_permissions() -> Vec<Permission> {
    vec![Permission {
        display_name: "VSCode Access".to_string(),
        description: "Allows the plugin to control VSCode application.".to_string(),
        permission_type: PermissionType::Execute as i32,
        permission_level: PermissionLevel::Unspecified as i32,
        resource: vec![],
    }]
}

fn vscode_write_plugin_permissions() -> Vec<Permission> {
    vec![
        Permission {
            display_name: "VSCode Access".to_string(),
            description: "Allows the plugin to control VSCode application.".to_string(),
            permission_type: PermissionType::Execute as i32,
            permission_level: PermissionLevel::Unspecified as i32,
            resource: vec![],
        },
        Permission {
            display_name: "Filesystem Write".to_string(),
            description: "Allows the plugin to write files to the local filesystem.".to_string(),
            permission_type: PermissionType::FilesystemWrite as i32,
            permission_level: PermissionLevel::Unspecified as i32,
            resource: vec![],
        },
    ]
}

// ============================================================================
// Permission Check Helpers
// ============================================================================

fn _permission_check_backend(
    allow: Vec<PluginFunctionPermissions>,
    function_id: &str,
    required_perms: Vec<Permission>,
) -> Result<(), JsErrorBox> {
    let required_permissions = sapphillon_core::permission::Permissions {
        permissions: required_perms,
    };

    let allowed_permissions = {
        let permissions_vec = allow;
        permissions_vec
            .into_iter()
            .find(|p| p.plugin_function_id == function_id || p.plugin_function_id == "*")
            .map(|p| p.permissions)
            .unwrap_or_else(|| sapphillon_core::permission::Permissions {
                permissions: vec![],
            })
    };

    let permission_check_result = check_permission(&allowed_permissions, &required_permissions);

    match permission_check_result {
        CheckPermissionResult::Ok => Ok(()),
        CheckPermissionResult::MissingPermission(perm) => Err(JsErrorBox::new(
            "PermissionDenied. Missing Permissions:",
            perm.to_string(),
        )),
    }
}

fn permission_check(
    state: &mut OpState,
    function_id: &str,
    required_perms: Vec<Permission>,
) -> Result<(), JsErrorBox> {
    let data = state
        .borrow::<Arc<Mutex<OpStateWorkflowData>>>()
        .lock()
        .unwrap();
    let allowed = match &data.get_allowed_permissions() {
        Some(p) => p.clone(),
        None => vec![],
    };
    _permission_check_backend(allowed, function_id, required_perms)?;
    Ok(())
}

// ============================================================================
// VSCode Command Execution Helpers
// ============================================================================

fn run_vscode_command(args: &[&str]) -> anyhow::Result<String> {
    let output = if cfg!(target_os = "windows") {
        Command::new("cmd")
            .arg("/C")
            .arg("code")
            .args(args)
            .output()
    } else {
        Command::new("code").args(args).output()
    }?;

    if output.status.success() {
        Ok("ok".to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        Err(anyhow::anyhow!(
            "VSCode command failed with status {}: {}",
            output.status,
            stderr
        ))
    }
}

// ============================================================================
// Op2 Functions (Deno Runtime Operations)
// ============================================================================

#[op2]
#[string]
fn op2_vscode_open_folder(
    state: &mut OpState,
    #[string] path: String,
) -> std::result::Result<String, JsErrorBox> {
    permission_check(
        state,
        &vscode_open_folder_plugin_function().function_id,
        vscode_plugin_permissions(),
    )?;

    match run_vscode_command(&[&path]) {
        Ok(output) => Ok(output),
        Err(e) => Err(JsErrorBox::new("Error", e.to_string())),
    }
}

#[op2]
#[string]
fn op2_vscode_open_file(
    state: &mut OpState,
    #[string] path: String,
) -> std::result::Result<String, JsErrorBox> {
    permission_check(
        state,
        &vscode_open_file_plugin_function().function_id,
        vscode_plugin_permissions(),
    )?;

    match run_vscode_command(&[&path]) {
        Ok(output) => Ok(output),
        Err(e) => Err(JsErrorBox::new("Error", e.to_string())),
    }
}

#[op2]
#[string]
fn op2_vscode_write_file(
    state: &mut OpState,
    #[string] path: String,
    #[string] content: String,
) -> std::result::Result<String, JsErrorBox> {
    permission_check(
        state,
        &vscode_write_file_plugin_function().function_id,
        vscode_write_plugin_permissions(),
    )?;

    // Write content to file
    std::fs::write(&path, &content).map_err(|e| JsErrorBox::new("Error", e.to_string()))?;

    // Open file in VSCode
    match run_vscode_command(&[&path]) {
        Ok(output) => Ok(output),
        Err(e) => Err(JsErrorBox::new("Error", e.to_string())),
    }
}

#[op2]
#[string]
fn op2_vscode_close_workspace(state: &mut OpState) -> std::result::Result<String, JsErrorBox> {
    permission_check(
        state,
        &vscode_close_workspace_plugin_function().function_id,
        vscode_plugin_permissions(),
    )?;

    // Close all VSCode windows
    match run_vscode_command(&["--close-all"]) {
        Ok(output) => Ok(output),
        Err(e) => Err(JsErrorBox::new("Error", e.to_string())),
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use sapphillon_core::proto::sapphillon::v1::PermissionType;
    use sapphillon_core::workflow::CoreWorkflowCode;

    #[test]
    fn test_vscode_open_folder_in_workflow() {
        // Create a temp directory
        let tmp_dir = std::env::temp_dir();
        let tmp_path = tmp_dir.to_str().unwrap().to_string();
        let escaped_path = tmp_path.replace(r"\", r"\\");

        let code = format!(
            "const path = {escaped_path:?}; const result = vscode.open_folder(path); console.log(result);"
        );

        let perm = PluginFunctionPermissions {
            plugin_function_id: vscode_open_folder_plugin_function().function_id,
            permissions: sapphillon_core::permission::Permissions {
                permissions: vec![Permission {
                    display_name: "VSCode Access".to_string(),
                    description: "Allows VSCode control".to_string(),
                    permission_type: PermissionType::Execute as i32,
                    permission_level: PermissionLevel::Unspecified as i32,
                    resource: vec![],
                }],
            },
        };

        let mut workflow = CoreWorkflowCode::new(
            "test".to_string(),
            code.to_string(),
            vec![core_vscode_plugin_package()],
            1,
            Some(perm.clone()),
            Some(perm),
        );

        workflow.run();
        assert_eq!(workflow.result.len(), 1);
        // The result might be "ok" if VSCode is installed, or an error if not
        // We just check that we got some result
        assert!(!workflow.result[0].result.is_empty());
    }

    #[test]
    fn test_permission_denied_in_workflow() {
        let code = r#"
            vscode.open_folder("/tmp");
        "#;

        // Use empty permissions list to trigger permission denial
        let perm = PluginFunctionPermissions {
            plugin_function_id: vscode_open_folder_plugin_function().function_id,
            permissions: sapphillon_core::permission::Permissions {
                permissions: vec![],
            },
        };

        let mut workflow = CoreWorkflowCode::new(
            "test".to_string(),
            code.to_string(),
            vec![core_vscode_plugin_package()],
            1,
            Some(perm.clone()),
            Some(perm),
        );

        workflow.run();
        assert_eq!(workflow.result.len(), 1);
        let actual = &workflow.result[0].result;
        assert!(
            actual.to_lowercase().contains("permission denied") || actual.contains("Uncaught"),
            "Unexpected workflow result: {actual}"
        );
    }
}
