#include "DW_ABTestingEnrollBindings.h"

extern "C" bool DW_LocalBackend_IsEnabled();

extern "C" bool bdABTestingEnrollRequest_RestSerializeRequest(void *, void *builder)
{
    // Preserve Replay's URI, method, bodyless request and native MIME routing.
    // All imports and field offsets in this header come from the original
    // instruction stream during the private compilation sequence.
    auto *auth = DW_AB_BuilderAuth(DW_AB_BuilderLobby(builder));
    auto *uri = DW_AB_BuilderURI(builder);
    const char *cursor = "abtesting/v2/users/{account_type}-{user_id}/enrollments/";
    DW_AB_ResetPath(uri);
    DW_AB_AppendBlock(uri, &cursor);
    DW_AB_AppendString(uri, DW_AB_AccountType(auth));
    DW_AB_AppendBlock(uri, &cursor);
    DW_AB_AppendNumber(uri, DW_AB_UserID(auth));
    DW_AB_AppendBlock(uri, &cursor);
    // Original formatPath instantiates three no-op dummy arguments followed
    // by appendNextBlock. Retain the latter calls and their error handling.
    for (unsigned dummy = 0; dummy < 3; ++dummy)
        DW_AB_AppendBlock(uri, &cursor);
    if (!DW_AB_URIIsOK(uri))
        DW_AB_ResetPath(uri);
    if (!DW_AB_URIIsOK(uri) || !DW_AB_SetMethod(builder, DW_AB_PostMethod))
        return false;
    if (!DW_AB_SetAccept(DW_AB_BuilderHeaders(builder), DW_AB_JsonMime) ||
        !DW_AB_SetResource(builder, "abtesting", "enroll"))
        return false;
    return !DW_LocalBackend_IsEnabled() || DW_AB_SetService(builder, "abtesting");
}
