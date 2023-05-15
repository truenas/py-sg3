# cython: language_level=3, c_string_type=unicode, c_string_encoding=default

from pxd cimport libsgutils

from libc.string cimport memset, memcpy, memcmp, strlen
from libc.stdlib cimport free
from libc.stdio cimport snprintf
from libc.errno cimport errno
from libc.stdint cimport uint8_t, uint32_t

from enum import IntEnum
from os import strerror


class SES_ETC(IntEnum):
    UNSPECIFIED_ETC = 0x0
    DEVICE_ETC = 0x1
    POWER_SUPPLY_ETC = 0x2
    COOLING_ETC = 0x3
    TEMPERATURE_ETC = 0x4
    DOOR_ETC = 0x5
    AUD_ALARM_ETC = 0x6
    ENC_SCELECTR_ETC = 0x7
    SCC_CELECTR_ETC = 0x8
    NV_CACHE_ETC = 0x9
    INV_OP_REASON_ETC = 0xa
    UI_POWER_SUPPLY_ETC = 0xb
    DISPLAY_ETC = 0xc
    KEY_PAD_ETC = 0xd
    ENCLOSURE_ETC = 0xe
    SCSI_PORT_TRAN_ETC = 0xf
    LANGUAGE_ETC = 0x10
    COMM_PORT_ETC = 0x11
    VOLT_SENSOR_ETC = 0x12
    CURR_SENSOR_ETC = 0x13
    SCSI_TPORT_ETC = 0x14
    SCSI_IPORT_ETC = 0x15
    SIMPLE_SUBENC_ETC = 0x16
    ARRAY_DEV_ETC = 0x17
    SAS_EXPANDER_ETC = 0x18
    SAS_CONNECTOR_ETC = 0x19


cdef class EnclosureDevice(object):

    cdef const char* device
    cdef int dev_fd
    cdef libsgutils.sg_pt_base * ptvp
    cdef libsgutils.type_desc_hdr_t desc_hdrs[1024]
    cdef int desc_hdrs_count
    cdef unsigned char * rsp_buff
    cdef unsigned char * free_rsp_buff
    cdef unsigned char * tmp_buff
    cdef unsigned char * free_tmp_buff
    cdef unsigned int MX_ALLOC_LEN
    cdef unsigned int CONFIGURATION_DPC
    cdef unsigned int ENC_STATUS_DPC
    cdef unsigned int ELEM_DESC_DPC
    cdef char r_buff[32 * 1024]
    cdef char * start
    cdef char * end

    def __cinit__(self, device):
        self.device = device
        self.dev_fd = -1
        self.desc_hdrs_count = 0
        self.ptvp = NULL
        self.rsp_buff = NULL
        self.tmp_buff = NULL
        self.free_rsp_buff = NULL
        self.free_tmp_buff = NULL
        self.MX_ALLOC_LEN = ((64 * 1024) - 4)
        self.CONFIGURATION_DPC = 0x1
        self.ENC_STATUS_DPC = 0x2
        self.ELEM_DESC_DPC = 0x7

        with nogil:
            self.dev_fd = libsgutils.sg_cmds_open_device(self.device, True, 0)
            if self.dev_fd < 0:
                raise OSError(errno, strerror(errno), self.device)

            self.ptvp = libsgutils.construct_scsi_pt_obj_with_fd(self.dev_fd, 0)
            if self.ptvp == NULL:
                raise OSError(-12, strerror(-12), self.device) # ENOMEM
            libsgutils.clear_scsi_pt_obj(self.ptvp)
            self.clear_r_buff()

    def __dealloc__(self):
        with nogil:
            if self.dev_fd >= 0:
                libsgutils.sg_cmds_close_device(self.dev_fd)
            if self.ptvp != NULL:
                libsgutils.destruct_scsi_pt_obj(self.ptvp)

    cdef int alloc_resp_buffs(self) nogil:
        self.rsp_buff = libsgutils.sg_memalign(self.MX_ALLOC_LEN, 0, &self.free_rsp_buff, False)
        if self.rsp_buff == NULL:
            return -1
        memset(self.rsp_buff, 0, self.MX_ALLOC_LEN)
        self.tmp_buff = libsgutils.sg_memalign(self.MX_ALLOC_LEN, 0, &self.free_tmp_buff, False)
        if self.tmp_buff == NULL:
            return -1
        memset(self.tmp_buff, 0, self.MX_ALLOC_LEN)
        return 0

    cdef void free_resp_buffs(self) nogil:
        if self.free_rsp_buff != NULL:
            free(self.free_rsp_buff)
        if self.free_tmp_buff != NULL:
            free(self.free_tmp_buff)
        self.rsp_buff = NULL
        self.tmp_buff = NULL
        self.free_rsp_buff = NULL
        self.free_tmp_buff = NULL

    cdef void clear_r_buff(self) nogil:
        memset(self.r_buff, 0, sizeof(self.r_buff))
        self.start = self.r_buff
        self.end = self.r_buff + sizeof(self.r_buff)

    cdef void clear_ptvp(self) nogil:
        if self.ptvp != NULL:
            libsgutils.clear_scsi_pt_obj(self.ptvp)

    cdef void clear_objs(self) nogil:
        self.free_resp_buffs()
        self.clear_ptvp()

    cdef char * etype_str(self, int elem_code, char * buff, int buff_len) nogil:
        cdef int len
        with gil:
            element_dict = {
                SES_ETC.UNSPECIFIED_ETC : ["un", "Unspecified"],
                SES_ETC.DEVICE_ETC : ["dev", "Device slot"],
                SES_ETC.POWER_SUPPLY_ETC : ["ps", "Power supply"],
                SES_ETC.COOLING_ETC : ["coo", "Cooling"],
                SES_ETC.TEMPERATURE_ETC : ["ts", "Temperature sensor"],
                SES_ETC.DOOR_ETC : ["do", "Door"],
                SES_ETC.AUD_ALARM_ETC : ["aa", "Audible alarm"],
                SES_ETC.ENC_SCELECTR_ETC : ["esc", "Enclosure services controller electronics"],
                SES_ETC.SCC_CELECTR_ETC : ["sce", "SCC controller electronics"],
                SES_ETC.NV_CACHE_ETC : ["nc", "Nonvolatile cache"],
                SES_ETC.INV_OP_REASON_ETC : ["ior", "Invalid operation reason"],
                SES_ETC.UI_POWER_SUPPLY_ETC : ["ups", "Uninterruptible power supply"],
                SES_ETC.DISPLAY_ETC : ["dis", "Display"],
                SES_ETC.KEY_PAD_ETC : ["kpe", "SCSI port/transceiver"],
                SES_ETC.ENCLOSURE_ETC : ["enc", "Enclosure"],
                SES_ETC.SCSI_PORT_TRAN_ETC : ["sp", "SCSI port/transceiver"],
                SES_ETC.LANGUAGE_ETC : ["lan", "Language"],
                SES_ETC.COMM_PORT_ETC : ["cp", "Communication port"],
                SES_ETC.VOLT_SENSOR_ETC : ["vs", "Voltage sensor"],
                SES_ETC.CURR_SENSOR_ETC : ["cs", "Current sensor"],
                SES_ETC.SCSI_TPORT_ETC : ["stp", "SCSI target port"],
                SES_ETC.SCSI_IPORT_ETC : ["sip", "SCSI initiator port"],
                SES_ETC.SIMPLE_SUBENC_ETC : ["ss", "Simple subenclosure"],
                SES_ETC.ARRAY_DEV_ETC : ["arr", "Array device slot"],
                SES_ETC.SAS_EXPANDER_ETC : ["sse", "SAS expander"],
                SES_ETC.SAS_CONNECTOR_ETC : ["ssc", "SAS connector"]
            }
            if elem_code in element_dict:
                return element_dict[elem_code][1]

        if elem_code < 0x80:
            snprintf(buff, buff_len - 1, "[0x%x]", elem_code)
        else:
            snprintf(buff, buff_len - 1, "vendor specific [0x%x]", elem_code)

        return buff

    cdef int get_diagnostic_page(self, int page_code, unsigned char * buff, int * rsp_len) nogil:
        cdef int ret = -1
        cdef int resid
        cdef int buff_size = self.MX_ALLOC_LEN

        ret = libsgutils.sg_ll_receive_diag_pt(self.ptvp, True, page_code, buff, buff_size, 0, &resid, False, 0)
        if 0 == ret:
            rsp_len[0] = libsgutils.sg_get_unaligned_be16(buff + 2) + 4
            if rsp_len[0] > buff_size:
                if buff_size > 8:
                    self.start += snprintf(self.start, self.end - self.start, "Warning: Response buffer was too small.\n")
                    if self.start >= self.end:
                        self.clear_objs()
                        raise OSError(-1, "Return buffer is full.")
                if resid > 0:
                    buff_size -= resid
            elif resid > 0:
                buff_size -= resid
            if rsp_len[0] > buff_size:
                    rsp_len[0] = buff_size
            if rsp_len[0] < 0:
                self.start += snprintf(self.start, self.end - self.start, "Warning: resid=%d too large, implies -ve reply length: %d\n", resid, rsp_len[0])
                if self.start >= self.end:
                    self.clear_objs()
                    raise OSError(-1, "Return buffer is full.")
                rsp_len[0] = 0
            if rsp_len[0] > 1 and page_code != buff[0]:
                if 0x9 == buff[0] and 1 & buff[1]:
                    self.start += snprintf(self.start, self.end - self.start, "Enclosure busy, try again later\n")
                    if self.start >= self.end:
                        self.clear_objs()
                        raise OSError(-1, "Return buffer is full.")
                elif 0x8 == buff[0]:
                    self.start += snprintf(self.start, self.end - self.start, "Enclosure only supports Short Enclosure Status: 0x%x\n", buff[1])
                    if self.start >= self.end:
                        self.clear_objs()
                        raise OSError(-1, "Return buffer is full.")
                else:
                    self.start += snprintf(self.start, self.end - self.start, "Invalid response, wanted page code: 0x%x but got 0x%x\n", page_code, buff[0])
                    if self.start >= self.end:
                        self.clear_objs()
                        raise OSError(-1, "Return buffer is full.")
                return -2

        return ret

    cdef int build_tdhs(self, uint32_t *generation, libsgutils.enclosure_info * primary_ip) nogil:
        cdef int ret, num_subs, sum_type_dheaders, el
        cdef int len = -1
        cdef uint8_t * bp
        cdef uint8_t * last_bp

        ret = self.get_diagnostic_page(self.CONFIGURATION_DPC, self.tmp_buff, &len)
        if ret:
            self.start += snprintf(self.start, self.end - self.start, "Could not read config page.\n")
            if self.start >= self.end:
                self.clear_objs()
                raise OSError(-1, "Return buffer is full.")
            return -1
        if len < 4:
            if 0 == ret:
                self.desc_hdrs_count += 1
            return -1

        num_subs = self.tmp_buff[1] + 1
        sum_type_dheaders = el = 0
        last_bp = self.tmp_buff + len - 1
        bp = self.tmp_buff + 8
        generation[0] = libsgutils.sg_get_unaligned_be32(self.tmp_buff + 4)

        for k in range (num_subs):
            if bp + 3 > last_bp:
                self.start += snprintf(self.start, self.end - self.start, "Config too short.\n")
                if self.start >= self.end:
                    self.clear_objs()
                    raise OSError(-1, "Return buffer is full.")
                return -1
            el = bp[3] + 4
            sum_type_dheaders += bp[2]
            if el < 40:
                self.start += snprintf(self.start, self.end - self.start, "Short enc descriptor len=%d ??\n", el)
                if self.start >= self.end:
                    self.clear_objs()
                    raise OSError(-1, "Return buffer is full.")
                bp += el
                continue
            if 0 == k:
                primary_ip.have_info += 1
                primary_ip.rel_esp_id = (bp[0] & 0x70) >> 4
                primary_ip.num_esp = (bp[0] & 0x7)
                memcpy(primary_ip.enc_log_id, bp + 4, 8)
                memcpy(primary_ip.enc_vendor_id, bp + 12, 8)
                memcpy(primary_ip.product_id, bp + 20, 16)
                memcpy(primary_ip.product_rev_level, bp + 36, 4)
            bp += el

        for k in range (sum_type_dheaders):
            if bp + 3 > last_bp:
                self.start += snprintf(self.start, self.end - self.start, "Config too short.\n")
                if self.start >= self.end:
                    self.clear_objs()
                    raise OSError(-1, "Return buffer is full.")
                return -1
            if k >= 1024:
                self.start += snprintf(self.start, self.end - self.start, "Too many elements.\n")
                if self.start >= self.end:
                    self.clear_objs()
                    raise OSError(-1, "Return buffer is full.")
                return -1
            self.desc_hdrs[k].etype = bp[0]
            self.desc_hdrs[k].num_elements = bp[1]
            self.desc_hdrs[k].se_id = bp[2]
            self.desc_hdrs[k].txt_len = bp[3]
            bp += 4

        if 0 == sum_type_dheaders:
            self.desc_hdrs_count += 1

        return sum_type_dheaders

    cdef int sg_inquiry(self) nogil:
        cdef int ret = -1, pd_type = 0
        cdef int resid
        cdef char buff[128]
        cdef char * cp

        ret = libsgutils.sg_ll_inquiry_pt(self.ptvp, False, 0, self.rsp_buff, 36, 0, &resid, False, 0)
        if ret != 0:
            self.start += snprintf(self.start, self.end - self.start, "%s does not respond to SCSI INQUIRY!\n", self.device)
            if self.start >= self.end:
                self.clear_objs()
                raise OSError(-1, "Return buffer is full.")
            return -1
        self.start += snprintf(self.start, self.end - self.start, "  %.8s  %.16s  %.4s\n", self.rsp_buff + 8, self.rsp_buff + 16, self.rsp_buff + 32)
        if self.start >= self.end:
            self.clear_objs()
            raise OSError(-1, "Return buffer is full.")
        pd_type = 0x1f & self.rsp_buff[0]
        if 0xD != pd_type:
            cp = libsgutils.sg_get_pdt_str(pd_type, sizeof(buff), buff)
            if 0x40 & self.rsp_buff[6]:
                self.start += snprintf(self.start, self.end - self.start, "    %s device has EncServ bit set.\n", cp)
                if self.start >= self.end:
                    self.clear_objs()
                    raise OSError(-1, "Return buffer is full.")
            elif 0 != memcmp(b"NVMe", self.rsp_buff + 8, 4):
                self.start += snprintf(self.start, self.end - self.start, "    %s device (not an enclosure).\n", cp)
                if self.start >= self.end:
                    self.clear_objs()
                    raise OSError(-1, "Return buffer is full.")
                return -1
        self.clear_ptvp()
        return 0

    def get_element_descriptor(self):
        cdef int len = -1
        cdef int num_ths, desc_len
        cdef uint32_t gen, ref_gen
        cdef uint8_t * bp
        cdef uint8_t * last_bp
        cdef char el_buff[64]
        cdef libsgutils.enclosure_info info
        cdef libsgutils.type_desc_hdr_t * tp
        cdef int k, j

        with nogil:
            if self.alloc_resp_buffs() != 0:
                self.clear_objs()
                raise OSError(-12, "Out of memory.")
            self.clear_r_buff()
            if self.sg_inquiry() != 0:
                self.clear_objs()
                raise OSError(-1, bytes(self.r_buff, encoding='ascii').decode())
            num_ths = self.build_tdhs(&ref_gen, &info)
            if num_ths < 0:
                self.clear_objs()
                raise OSError(-1, bytes(self.r_buff, encoding='ascii').decode())
            if 1 == self.desc_hdrs_count and info.have_info:
                self.start += snprintf(self.start, self.end - self.start, "  Primary enclosure logical identifier (hex): ")
                if self.start >= self.end:
                    self.clear_objs()
                    raise OSError(-1, "Return buffer is full.")
                for i in range(8):
                    self.start += snprintf(self.start, self.end - self.start, "%02x", info.enc_log_id[i])
                    if self.start >= self.end:
                        self.clear_objs()
                        raise OSError(-1, "Return buffer is full.")
                self.start += snprintf(self.start, self.end - self.start, "\n")
                if self.start >= self.end:
                    self.clear_objs()
                    raise OSError(-1, "Return buffer is full.")

            self.clear_ptvp()
            if self.get_diagnostic_page(self.ELEM_DESC_DPC, self.rsp_buff, &len) != 0:
                raise OSError(-1, bytes(self.r_buff, encoding='ascii').decode())
            self.start += snprintf(self.start, self.end - self.start, "Element Descriptor diagnostic page:\n")
            if self.start >= self.end:
                self.clear_objs()
                raise OSError(-1, "Return buffer is full.")
            if len < 8:
                self.start += snprintf(self.start, self.end - self.start, "Element Descriptor: response too short.\n")
                if self.start >= self.end:
                    self.clear_objs()
                    raise OSError(-1, "Return buffer is full.")
                self.clear_objs()
                raise OSError(-1, bytes(self.r_buff, encoding='ascii').decode())

            last_bp = self.rsp_buff + len - 1
            gen = libsgutils.sg_get_unaligned_be32(self.rsp_buff + 4)
            self.start += snprintf(self.start, self.end - self.start, "  generation code: 0x%x\n", gen)
            if self.start >= self.end:
                self.clear_objs()
                raise OSError(-1, "Return buffer is full.")
            if gen != ref_gen:
                self.start += snprintf(self.start, self.end - self.start, "  <<state of enclosure changed, please try again>>\n")
                if self.start >= self.end:
                    self.clear_objs()
                    raise OSError(-1, "Return buffer is full.")
                self.clear_objs()
                raise OSError(-1, bytes(self.r_buff, encoding='ascii').decode())

            self.start += snprintf(self.start, self.end - self.start, "  element descriptor list (grouped by type):\n")
            if self.start >= self.end:
                self.clear_objs()
                raise OSError(-1, "Return buffer is full.")
            bp = self.rsp_buff + 8
            tp = self.desc_hdrs
            for k in range (0, num_ths):
                if bp + 3 > last_bp:
                    self.start += snprintf(self.start, self.end - self.start, "Element Descriptor: response too short.\n")
                    if self.start >= self.end:
                        self.clear_objs()
                        raise OSError(-1, "Return buffer is full.")
                    self.clear_objs()
                    raise OSError(-1, bytes(self.r_buff, encoding='ascii').decode())
                desc_len = libsgutils.sg_get_unaligned_be16(bp + 2) + 4
                memset(el_buff, 0, sizeof(el_buff))
                self.start += snprintf(self.start, self.end - self.start, "    Element type: %s, subenclosure id: %d [ti=%d]\n", self.etype_str(tp.etype, el_buff, sizeof(el_buff)), tp.se_id, k)
                if self.start >= self.end:
                    self.clear_objs()
                    raise OSError(-1, "Return buffer is full.")
                if desc_len > 4:
                    self.start += snprintf(self.start, self.end - self.start, "      Overall descriptor: %.*s\n", desc_len - 4, bp + 4)
                    if self.start >= self.end:
                        self.clear_objs()
                        raise OSError(-1, "Return buffer is full.")
                else:
                    self.start += snprintf(self.start, self.end - self.start, "      Overall descriptor: <empty>\n")
                    if self.start >= self.end:
                        self.clear_objs()
                        raise OSError(-1, "Return buffer is full.")
                bp += desc_len
                for j in range (0, tp.num_elements):
                    desc_len = libsgutils.sg_get_unaligned_be16(bp + 2) + 4
                    if desc_len > 4:
                        self.start += snprintf(self.start, self.end - self.start, "      Element %d descriptor: %.*s\n", j, desc_len - 4, bp + 4)
                        if self.start >= self.end:
                            self.clear_objs()
                            raise OSError(-1, "Return buffer is full.")
                    else:
                        self.start += snprintf(self.start, self.end - self.start, "      Element %d descriptor: <empty>\n", j)
                        if self.start >= self.end:
                            self.clear_objs()
                            raise OSError(-1, "Return buffer is full.")
                    bp += desc_len
                tp += 1
            self.clear_objs()
            with gil:
                return bytes(self.r_buff, encoding='ascii').decode()

    def get_configuration(self):
        cdef int len = -1, el = 0
        cdef int desc_len, num_subs, el_types = 0
        cdef uint32_t gen
        cdef uint8_t * bp
        cdef uint8_t * last_bp
        cdef uint8_t *text_bp
        cdef char el_buff[64]
        cdef libsgutils.type_desc_hdr_t * tp
        cdef int k, j

        with nogil:
            if self.alloc_resp_buffs() != 0:
                self.clear_objs()
                raise OSError(-12, "Out of memory.")
            self.clear_r_buff()
            if self.sg_inquiry() != 0:
                self.clear_objs()
                raise OSError(-1, bytes(self.r_buff, encoding='ascii').decode())

            if self.get_diagnostic_page(self.CONFIGURATION_DPC, self.rsp_buff, &len) != 0:
                raise OSError(-1, bytes(self.r_buff, encoding='ascii').decode())
            self.start += snprintf(self.start, self.end - self.start, "Configuration diagnostic page:\n")
            if self.start >= self.end:
                self.clear_objs()
                raise OSError(-1, "Return buffer is full.")
            if len < 4:
                self.start += snprintf(self.start, self.end - self.start, "SES Confgiruation: Response too short.\n")
                if self.start >= self.end:
                    self.clear_objs()
                    raise OSError(-1, "Return buffer is full.")
                self.clear_objs()
                raise OSError(-1, bytes(self.r_buff, encoding='ascii').decode())

            num_subs = self.rsp_buff[1] + 1
            self.start += snprintf(self.start, self.end - self.start, "  number of secondary subenclosures: %d\n", num_subs - 1)
            if self.start >= self.end:
                self.clear_objs()
                raise OSError(-1, "Return buffer is full.")
            gen = libsgutils.sg_get_unaligned_be32(self.rsp_buff + 4)
            self.start += snprintf(self.start, self.end - self.start, "  generation code: 0x%x\n", gen)
            if self.start >= self.end:
                self.clear_objs()
                raise OSError(-1, "Return buffer is full.")

            last_bp = self.rsp_buff + len - 1
            bp = self.rsp_buff + 8
            self.start += snprintf(self.start, self.end - self.start, "  enclosure descriptor list\n")
            if self.start >= self.end:
                self.clear_objs()
                raise OSError(-1, "Return buffer is full.")
            for k in range(0, num_subs):
                if bp + 3 > last_bp:
                    self.start += snprintf(self.start, self.end - self.start, "SES Confgiruation: Response too short.\n")
                    if self.start >= self.end:
                        self.clear_objs()
                        raise OSError(-1, "Return buffer is full.")
                    self.clear_objs()
                    raise OSError(-1, bytes(self.r_buff, encoding='ascii').decode())
                el = bp[3] + 4
                el_types += bp[2]
                if bp[1] != 0:
                    self.start += snprintf(self.start, self.end - self.start, "    Subenclosure identifier: %d\n", bp[1])
                    if self.start >= self.end:
                        self.clear_objs()
                        raise OSError(-1, "Return buffer is full.")
                else:
                    self.start += snprintf(self.start, self.end - self.start, "    Subenclosure identifier: %d [primary]\n", bp[1])
                    if self.start >= self.end:
                        self.clear_objs()
                        raise OSError(-1, "Return buffer is full.")
                self.start += snprintf(self.start, self.end - self.start, "      relative ES process id: %d, number of ES processes: %d\n", ((bp[0] & 0x70) >> 4), (bp[0] & 0x7))
                if self.start >= self.end:
                    self.clear_objs()
                    raise OSError(-1, "Return buffer is full.")
                self.start += snprintf(self.start, self.end - self.start, "      number of type descriptor headers: %d\n", bp[2])
                if self.start >= self.end:
                    self.clear_objs()
                    raise OSError(-1, "Return buffer is full.")
                if el < 40:
                    self.start += snprintf(self.start, self.end - self.start, "      enc descriptor len=%d ??\n", el)
                    if self.start >= self.end:
                        self.clear_objs()
                        raise OSError(-1, "Return buffer is full.")
                    bp += el
                    continue
                self.start += snprintf(self.start, self.end - self.start, "      enclosure logical identifier (hex): ")
                if self.start >= self.end:
                    self.clear_objs()
                    raise OSError(-1, "Return buffer is full.")
                for j in range(8):
                    self.start += snprintf(self.start, self.end - self.start, "%02x", bp[4 + j])
                    if self.start >= self.end:
                        self.clear_objs()
                        raise OSError(-1, "Return buffer is full.")
                self.start += snprintf(self.start, self.end - self.start, "\n      enclosure vendor: %.8s  product: %.16s  rev: %.4s\n", bp + 12, bp + 20, bp + 36)
                if self.start >= self.end:
                    self.clear_objs()
                    raise OSError(-1, "Return buffer is full.")
                bp += el

            self.start += snprintf(self.start, self.end - self.start, "  type descriptor header and text list\n")
            if self.start >= self.end:
                self.clear_objs()
                raise OSError(-1, "Return buffer is full.")
            text_bp = bp + (el_types * 4)
            for k in range (0, el_types):
                if bp + 3 > last_bp:
                    self.start += snprintf(self.start, self.end - self.start, "SES Confgiruation: Response too short.\n")
                    if self.start >= self.end:
                        self.clear_objs()
                        raise OSError(-1, "Return buffer is full.")
                    self.clear_objs()
                    raise OSError(-1, bytes(self.r_buff, encoding='ascii').decode())
                memset(el_buff, 0, sizeof(el_buff))
                self.start += snprintf(self.start, self.end - self.start, "    Element type: %s, subenclosure id: %d\n", self.etype_str(bp[0], el_buff, sizeof(el_buff)), bp[2])
                if self.start >= self.end:
                    self.clear_objs()
                    raise OSError(-1, "Return buffer is full.")
                self.start += snprintf(self.start, self.end - self.start, "      number of possible elements: %d\n", bp[1])
                if self.start >= self.end:
                    self.clear_objs()
                    raise OSError(-1, "Return buffer is full.")
                if bp[3] > 0:
                    if text_bp > last_bp:
                        self.start += snprintf(self.start, self.end - self.start, "SES Confgiruation: Response too short.\n")
                        if self.start >= self.end:
                            self.clear_objs()
                            raise OSError(-1, "Return buffer is full.")
                        self.clear_objs()
                        raise OSError(-1, bytes(self.r_buff, encoding='ascii').decode())
                    self.start += snprintf(self.start, self.end - self.start, "      text: %.*s\n", bp[3], text_bp)
                    if self.start >= self.end:
                        self.clear_objs()
                        raise OSError(-1, "Return buffer is full.")
                    text_bp += bp[3]
                    bp += 4

            self.clear_objs()
            with gil:
                return bytes(self.r_buff, encoding='ascii').decode()

    def get_enclosure_status(self):
        cdef int len = -1
        cdef int num_ths, desc_len
        cdef uint32_t gen, ref_gen
        cdef uint8_t * bp
        cdef uint8_t * last_bp
        cdef char el_buff[64]
        cdef libsgutils.enclosure_info info
        cdef libsgutils.type_desc_hdr_t * tp
        cdef int k, j
        cdef bint invop, infob, noncrit, crit, unrecov

        with nogil:
            if self.alloc_resp_buffs() != 0:
                self.clear_objs()
                raise OSError(-12, "Out of memory.")
            self.clear_r_buff()
            if self.sg_inquiry() != 0:
                self.clear_objs()
                raise OSError(-1, bytes(self.r_buff, encoding='ascii').decode())
            num_ths = self.build_tdhs(&ref_gen, &info)
            if num_ths < 0:
                self.clear_objs()
                raise OSError(-1, bytes(self.r_buff, encoding='ascii').decode())
            if 1 == self.desc_hdrs_count and info.have_info:
                self.start += snprintf(self.start, self.end - self.start, "  Primary enclosure logical identifier (hex): ")
                if self.start >= self.end:
                    self.clear_objs()
                    raise OSError(-1, "Return buffer is full.")
                for i in range(8):
                    self.start += snprintf(self.start, self.end - self.start, "%02x", info.enc_log_id[i])
                    if self.start >= self.end:
                        self.clear_objs()
                        raise OSError(-1, "Return buffer is full.")
                self.start += snprintf(self.start, self.end - self.start, "\n")
                if self.start >= self.end:
                    self.clear_objs()
                    raise OSError(-1, "Return buffer is full.")

            self.clear_ptvp()
            if self.get_diagnostic_page(self.ENC_STATUS_DPC, self.rsp_buff, &len) != 0:
                raise OSError(-1, bytes(self.r_buff, encoding='ascii').decode())
            self.start += snprintf(self.start, self.end - self.start, "Enclosure Status diagnostic page:\n")
            if self.start >= self.end:
                self.clear_objs()
                raise OSError(-1, "Return buffer is full.")
            if len < 4:
                self.start += snprintf(self.start, self.end - self.start, "Enclosure Status: response too short.\n")
                if self.start >= self.end:
                    self.clear_objs()
                    raise OSError(-1, "Return buffer is full.")
                self.clear_objs()
                raise OSError(-1, bytes(self.r_buff, encoding='ascii').decode())

            invop = (self.rsp_buff[1] & 0x10) != 0
            infob = (self.rsp_buff[1] & 0x8) != 0
            noncrit = (self.rsp_buff[1] & 0x4) != 0
            crit = (self.rsp_buff[1] & 0x2) != 0
            unrecov = (self.rsp_buff[1] & 0x1) != 0
            self.start += snprintf(self.start, self.end - self.start, "  INVOP=%d, INFO=%d, NON-CRIT=%d, CRIT=%d, UNRECOV=%d\n", invop, infob, noncrit, crit, unrecov)
            if self.start >= self.end:
                self.clear_objs()
                raise OSError(-1, "Return buffer is full.")
            if len < 8:
                self.start += snprintf(self.start, self.end - self.start, "Enclosure Status: response too short.\n")
                if self.start >= self.end:
                    self.clear_objs()
                    raise OSError(-1, "Return buffer is full.")
                self.clear_objs()
                raise OSError(-1, bytes(self.r_buff, encoding='ascii').decode())

            last_bp = self.rsp_buff + len - 1
            gen = libsgutils.sg_get_unaligned_be32(self.rsp_buff + 4)
            self.start += snprintf(self.start, self.end - self.start, "  generation code: 0x%x\n", gen)
            if self.start >= self.end:
                self.clear_objs()
                raise OSError(-1, "Return buffer is full.")
            if gen != ref_gen:
                self.start += snprintf(self.start, self.end - self.start, "  <<state of enclosure changed, please try again>>\n")
                if self.start >= self.end:
                    self.clear_objs()
                    raise OSError(-1, "Return buffer is full.")
                self.clear_objs()
                raise OSError(-1, bytes(self.r_buff, encoding='ascii').decode())

            self.start += snprintf(self.start, self.end - self.start, "  status descriptor list\n")
            if self.start >= self.end:
                self.clear_objs()
                raise OSError(-1, "Return buffer is full.")
            bp = self.rsp_buff + 8
            tp = self.desc_hdrs
            for k in range(0, num_ths):
                if bp + 3 > last_bp:
                    self.start += snprintf(self.start, self.end - self.start, "Enclosure Status: response too short.\n")
                    if self.start >= self.end:
                        self.clear_objs()
                        raise OSError(-1, "Return buffer is full.")
                    self.clear_objs()
                    raise OSError(-1, bytes(self.r_buff, encoding='ascii').decode())
                self.start += snprintf(self.start, self.end - self.start, "    Element type: %s, subenclosure id: %d [ti=%d]\n", self.etype_str(tp.etype, el_buff, sizeof(el_buff)), tp.se_id, k)
                if self.start >= self.end:
                    self.clear_objs()
                    raise OSError(-1, "Return buffer is full.")
                self.start += snprintf(self.start, self.end - self.start, "      Overall descriptor:\n")
                if self.start >= self.end:
                    self.clear_objs()
                    raise OSError(-1, "Return buffer is full.")
                self.start += snprintf(self.start, self.end - self.start, "        %02x %02x %02x %02x\n", bp[0], bp[1], bp[2], bp[3])
                if self.start >= self.end:
                    self.clear_objs()
                    raise OSError(-1, "Return buffer is full.")
                bp += 4
                for j in range (0, tp.num_elements):
                    self.start += snprintf(self.start, self.end - self.start, "      Element %d descriptor:\n", j)
                    if self.start >= self.end:
                        self.clear_objs()
                        raise OSError(-1, "Return buffer is full.")
                    self.start += snprintf(self.start, self.end - self.start, "        %02x %02x %02x %02x\n", bp[0], bp[1], bp[2], bp[3])
                    if self.start >= self.end:
                        self.clear_objs()
                        raise OSError(-1, "Return buffer is full.")
                    bp += 4
                tp += 1

            self.clear_objs()
            with gil:
                return bytes(self.r_buff, encoding='ascii').decode()
