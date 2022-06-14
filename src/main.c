#include <psp2/kernel/modulemgr.h>
#include <psp2/kernel/clib.h>
#include <psp2/sysmodule.h>
#include <taihen.h>

typedef SceUInt64 SceNpTime;

#define SCE_NP_ENTITLEMENT_ID_SIZE (32)

typedef struct SceNpEntitlementId {
  unsigned char data[SCE_NP_ENTITLEMENT_ID_SIZE];
} SceNpEntitlementId;

typedef struct SceNpEntitlement {
    SceNpEntitlementId id;
    SceNpTime createdDate;
    SceNpTime expireDate;
    SceUInt32 type;
    SceInt32 remainingCount; /* may be negative */
    SceUInt32 consumedCount;
    char padding[4];
} SceNpEntitlement;

tai_hook_ref_t nphookref;
static SceUID nphook = 0;

tai_hook_ref_t lmhookref;
static SceUID lmhook = 0;

int sceNpAuthGetEntitlementById_patched(const unsigned char *ticket, SceSize ticketSize, const char *entId, SceNpEntitlement *ent)
{
    TAI_CONTINUE(int, nphookref, ticket, ticketSize, entId, ent);
    return 0;
}

int sceSysmoduleLoadModule_patched(SceSysmoduleModuleId id)
{
    int ret = TAI_CONTINUE(int, lmhookref, id);
    if (ret >= 0 && id == 0x25) {
        sceClibPrintf("Loaded sysmodule; %x\n", id);
        nphook = taiHookFunctionImport(&nphookref, TAI_MAIN_MODULE, TAI_ANY_LIBRARY, 0xF93842F0, sceNpAuthGetEntitlementById_patched);
        sceClibPrintf("Hook: 0x%08X\n", nphook);
    }
    return ret;
}

void _start() __attribute__ ((weak, alias ("module_start")));

int module_start() {
    tai_module_info_t info;

    sceClibMemset(&info, 0, sizeof(info));
    info.size = sizeof(info);

    taiGetModuleInfo(TAI_MAIN_MODULE, &info);

    lmhook = taiHookFunctionImport(&lmhookref, TAI_MAIN_MODULE, 0x03FCF19D, 0x79A0160A, sceSysmoduleLoadModule_patched);

    sceClibPrintf("Hook: 0x%08X\n", lmhook);

    return SCE_KERNEL_START_SUCCESS;
}

int module_stop() {
    taiHookRelease(lmhook, lmhookref);

    if (nphook > 0)
    {
        taiHookRelease(nphook, nphookref);
    }
    return SCE_KERNEL_STOP_SUCCESS;
}
