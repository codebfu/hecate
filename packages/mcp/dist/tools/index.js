// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later
import { registerCancelCommandTool } from "./cancel_command.js";
import { registerDownloadCommandArtifactTool } from "./download_command_artifact.js";
import { registerExecuteCommandTool } from "./execute_command.js";
import { registerGetCommandTool } from "./get_command.js";
import { registerGetMachineTool } from "./get_machine.js";
import { registerListCommandsTool } from "./list_commands.js";
import { registerListMachinesTool } from "./list_machines.js";
import { registerApprovePermissionRequestTool, registerApproveQueueCommandTool, registerAuthzTools, registerCancelQueueCommandTool, registerListActionQueueTool, registerListAuditEventsTool, registerListPermissionRequestsTool, registerReadEffectiveRightsTool, registerReadGrantAssignmentsTool, registerRejectPermissionRequestTool, registerRepoTools, registerRequestPermissionsTool, } from "./admin_tools.js";
import { registerUploadCommandArtifactTool } from "./upload_command_artifact.js";
export function registerTools(server, client) {
    return [
        registerListMachinesTool(server, client),
        registerGetMachineTool(server, client),
        registerGetCommandTool(server, client),
        registerListCommandsTool(server, client),
        registerExecuteCommandTool(server, client),
        registerCancelCommandTool(server, client),
        registerRequestPermissionsTool(server, client),
        registerReadGrantAssignmentsTool(server, client),
        registerReadEffectiveRightsTool(server, client),
        ...registerAuthzTools(server, client),
        registerListPermissionRequestsTool(server, client),
        registerApprovePermissionRequestTool(server, client),
        registerRejectPermissionRequestTool(server, client),
        registerListAuditEventsTool(server, client),
        registerListActionQueueTool(server, client),
        registerApproveQueueCommandTool(server, client),
        registerCancelQueueCommandTool(server, client),
        registerUploadCommandArtifactTool(server, client),
        registerDownloadCommandArtifactTool(server, client),
        ...registerRepoTools(server, client),
    ];
}
export { TOOL_SPECS } from "./specs.js";
//# sourceMappingURL=index.js.map