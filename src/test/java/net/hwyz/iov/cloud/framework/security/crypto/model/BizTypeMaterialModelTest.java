package net.hwyz.iov.cloud.framework.security.crypto.model;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * BizType 材料模型分流测试（FW-SEC-DSN-CR-013 §4.4/§4.5/§7.1）。
 * <p>
 * 根派生型显式标 {@code DERIVED_ROOT} 并走 {@code KeyProvisioningTemplate.deriveAndWrap}；
 * 非对称签名条目 {@code materialModel=null}，两个门面均 fail-closed；v1 尚无 RANDOM_MATERIAL 枚举项。
 */
class BizTypeMaterialModelTest {

    @Test
    void derivedRootEntriesAreClassifiedAndRoutable() {
        BizType[] derivedRoot = {
                BizType.V2C_COMM_ROOT,
                BizType.IMMO_GROUP_KEY,
                BizType.OTA_VEHICLE_ROOT,
                BizType.TBOX_DEVICE_ROOT,
                BizType.CCU_DEVICE_ROOT,
                BizType.CGW_DEVICE_ROOT,
                BizType.AD_DCU_DEVICE_ROOT,
                BizType.CPT_DCU_DEVICE_ROOT,
                BizType.PEPS_DEVICE_ROOT,
                BizType.KLD_DEVICE_ROOT
        };
        for (BizType type : derivedRoot) {
            assertEquals(KeyMaterialModel.DERIVED_ROOT, type.materialModel(), type.name());
            assertTrue(type.supportsDerivedRoot(), type.name());
            assertFalse(type.supportsRandomMaterial(), type.name());
            assertNotNull(type.prov(), type.name());
        }
    }

    @Test
    void asymmetricSigningEntryIsUnclassifiedAndRejectedByBothFacades() {
        BizType type = BizType.IDK_KTS_SIGNING;

        assertNull(type.materialModel());
        assertFalse(type.supportsDerivedRoot());
        assertFalse(type.supportsRandomMaterial());
    }

    @Test
    void v1HasNoRandomMaterialEntry() {
        for (BizType type : BizType.values()) {
            assertFalse(type.supportsRandomMaterial(), type.name() + " 不应在 v1 标为 RANDOM_MATERIAL");
        }
    }
}
