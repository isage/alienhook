#include <psp2/kernel/modulemgr.h>
#include <psp2/kernel/clib.h>
#include <psp2/sysmodule.h>
#include <taihen.h>

#define SCE_NP_ENTITLEMENT_ID_SIZE (32)

typedef SceUInt64 SceNpTime;
typedef int SceNpAuthRequestId;

typedef struct SceNpEntitlementId {
  unsigned char data[SCE_NP_ENTITLEMENT_ID_SIZE];
} SceNpEntitlementId;

typedef struct SceNpTicketVersion {
  unsigned short major;
  unsigned short minor;
} SceNpTicketVersion;

typedef struct SceNpEntitlement {
    SceNpEntitlementId id;
    SceNpTime createdDate;
    SceNpTime expireDate;
    SceUInt32 type;
    SceInt32 remainingCount; /* may be negative */
    SceUInt32 consumedCount;
    char padding[4];
} SceNpEntitlement;

typedef struct SceNpAuthRequestParameter {
    SceSize size;
    SceNpTicketVersion version;
    const char *serviceId;
    const void *cookie;
    SceSize cookieSize;
    const char *entitlementId;
    SceUInt32 consumedCount;
    int  (*ticketCb)(SceNpAuthRequestId, int, void *);
    void *cbArg;
} SceNpAuthRequestParameter;

#define NP_HOOKS 2

tai_hook_ref_t nphookref[NP_HOOKS];
static SceUID nphook[NP_HOOKS];

tai_hook_ref_t lmhookref;
static SceUID lmhook = 0;

int sceNpAuthGetEntitlementById_patched(const unsigned char *ticket, SceSize ticketSize, const char *entId, SceNpEntitlement *ent)
{
    TAI_CONTINUE(int, nphookref[0], ticket, ticketSize, entId, ent);
    sceClibPrintf("Faking entitlement\n");
    return 0;
}

int sceNpAuthCreateStartRequest_patched(const SceNpAuthRequestParameter *param)
{
    int ret = TAI_CONTINUE(int, nphookref[1], param);
    sceClibPrintf("sceNpAuthCreateStartRequest %x\n", ret);
    sceClibPrintf("Force-calling callback\n");
    param->ticketCb(ret, 1, param->cbArg);
    return ret;
}

int sceSysmoduleLoadModule_patched(SceSysmoduleModuleId id)
{
    int ret = TAI_CONTINUE(int, lmhookref, id);
    if (ret >= 0 && id == 0x25) {
        sceClibPrintf("Loaded sysmodule; %x\n", id);
        nphook[0] = taiHookFunctionImport(&nphookref[0], TAI_MAIN_MODULE, TAI_ANY_LIBRARY, 0xF93842F0, sceNpAuthGetEntitlementById_patched);
        sceClibPrintf("sceNpAuthGetEntitlementById Hook: 0x%08X\n", nphook[0]);

        nphook[1] = taiHookFunctionImport(&nphookref[1], TAI_MAIN_MODULE, TAI_ANY_LIBRARY, 0xED42079F, sceNpAuthCreateStartRequest_patched);
        sceClibPrintf("sceNpAuthCreateStartRequest Hook: 0x%08X\n", nphook[1]);
    }
    return ret;
}

void _start() __attribute__ ((weak, alias ("module_start")));

int module_start() {
    tai_module_info_t info;

    sceClibMemset(&nphook, 0, NP_HOOKS*sizeof(SceUID));

    sceClibMemset(&info, 0, sizeof(info));
    info.size = sizeof(info);

    taiGetModuleInfo(TAI_MAIN_MODULE, &info);

    lmhook = taiHookFunctionImport(&lmhookref, TAI_MAIN_MODULE, 0x03FCF19D, 0x79A0160A, sceSysmoduleLoadModule_patched);

    sceClibPrintf("sceSysmoduleLoadModule Hook: 0x%08X\n", lmhook);

    return SCE_KERNEL_START_SUCCESS;
}

int module_stop() {
    taiHookRelease(lmhook, lmhookref);

    for (int i = 0; i < NP_HOOKS; ++i)
    {
        if (nphook[i] > 0)
        {
            taiHookRelease(nphook[i], nphookref[i]);
        }
    }
    return SCE_KERNEL_STOP_SUCCESS;
}
