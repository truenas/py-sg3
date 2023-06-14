# cython: language_level=3, c_string_type=unicode, c_string_encoding=default

from pxd cimport libsgutils

from libc.string cimport memset, memcpy, memcmp, strlen
from libc.stdlib cimport malloc, free
from libc.stdio cimport snprintf
from libc.errno cimport errno
from libc.stdint cimport uint8_t, uint32_t, uint64_t

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

    def get_acron2locs(self, index, cmd):
        acron2loc = {
            SES_ETC.DEVICE_ETC : {
                'active': [2, 7, 1, None], 'bypa': [3, 3, 1, 'bypass port A'], 'bypb': [3, 2, 1, 'bypass port B'],
                'devoff': [3, 4, 1, None], 'dnr': [2, 6, 1, 'do not remove'], 'fault': [3, 5, 1, None],
                'ident': [2, 1, 1, 'flash LED'], 'insert': [2, 3, 1, None], 'locate': [2, 1, 1, 'flash LED'],
                'missing': [2, 4, 1, None], 'remove': [2, 2, 1, None]
            },
            SES_ETC.POWER_SUPPLY_ETC : {
                'dnr': [1, 6, 1, 'do not remove'], 'fail': [3, 6, 1, None], 'ident': [1, 7, 1, 'flash LED'],
                'locate': [1, 7, 1, 'flash LED'], 'off': [3, 4, 1, 'Not providing power'],
                'on': [3, 5, 1, '0: turn (remain) off; 1: turn on'], 'overcurrent': [2, 1, 1, 'DC overcurrent'],
                'overvoltage': [2, 3, 1, 'DC overvoltage'], 'overvoltage_warn': [1, 3, 1, 'DC overvoltage warning'],
                'undervoltage': [2, 2, 1, 'DC undervoltage'], 'undervoltage_warn': [1, 2, 1, 'DC undervoltage warning']
            },
            SES_ETC.COOLING_ETC : {
                'dnr': [1, 6, 1, 'do not remove'], 'fail': [3, 6, 1, None], 'hotswap': [3, 7, 1, None], 'ident': [1, 7, 1, 'flash LED'],
                'locate': [1, 7, 1, 'flash LED'], 'off': [3, 4, 1, 'Not providing cooling'], 'on': [3, 5, 1, None],
                'speed_act': [1, 2, 11, 'actual speed (rpm / 10)'], 'speed_code': [3, 2, 3, '0: leave; 1: lowest... 7: highest']
            },
            SES_ETC.TEMPERATURE_ETC : {
                'fail': [3, 6, 1, None], 'ident': [1, 7, 1, 'flash LED'], 'locate': [1, 7, 1, 'flash LED'],
                'offset_temp': [1, 5, 6, 'Offset for reference temperature'], 'overtemp_fail': [3, 3, 1, 'Overtemperature failure'],
                'overtemp_warn': [3, 2, 1, 'Overtemperature warning'], 'rqst_override': [3, 7, 1, 'Request(ed) override'],
                'temp': [2, 7, 8, '(Requested) temperature'], 'undertemp_fail': [3, 1, 1, 'Undertemperature failure'],
                'undertemp_warn': [3, 0, 1, 'Undertemperature warning']
            },
            SES_ETC.DOOR_ETC : {
                'fail': [1, 6, 1, None], 'ident': [1, 7, 1, 'flash LED'], 'locate': [1, 7, 1, 'flash LED'],'open': [3, 1, 1, None],
                'unlock': [3, 0, 1, None]
            },
            SES_ETC.AUD_ALARM_ETC : {
                'fail': [1, 6, 1, None], 'ident': [1, 7, 1, None], 'info': [3, 3, 1, 'emits warning tone when set'],
                'locate': [1, 7, 1, None], 'mute': [3, 6, 1, 'control only: mute the alarm'],
                'muted': [3, 6, 1, 'status only: alarm is muted'], 'remind': [3, 4, 1, None],
                'rqst_mute': [3, 7, 1, 'status only: alarm was manually muted'], 'urgency': [3, 3, 4, None]
            },
            SES_ETC.ENC_SCELECTR_ETC : {
                'dnr': [1, 5, 1, 'do not remove'], 'fail': [1, 6, 1, None], 'hotswap': [3, 7, 1, None],
                'hw_reset': [1, 2, 1, 'hardware reset'], 'ident': [1, 7, 1, 'flash LED'], 'locate': [1, 7, 1, 'flash LED'],
                'report': [2, 0, 1, None], 'select_element': [2, 0, 1, None], 'sw_reset': [1, 3, 1, 'software reset']
            },
            SES_ETC.SCC_CELECTR_ETC : {
                'fail': [3, 6, 1, None], 'ident': [1, 7, 1, 'flash LED'], 'locate': [1, 7, 1, 'flash LED'], 'report': [2, 0, 1, None]
            },
            SES_ETC.NV_CACHE_ETC : {
                'fail': [3, 6, 1, None], 'ident': [1, 7, 1, 'flash LED'], 'locate': [1, 7, 1, 'flash LED'], 'size': [2, 7, 16, None],
                'size_mult': [1, 1, 2, None]
            },
            SES_ETC.UI_POWER_SUPPLY_ETC : {
                'ac_fail': [2, 4, 1, None], 'ac_hi': [2, 6, 1, None], 'ac_lo': [2, 7, 1, None], 'ac_qual': [2, 5, 1, None],
                'batt_fail': [3, 1, 1, None], 'bpf': [3, 0, 1, None], 'dc_fail': [2, 3, 1, None], 'dnr': [3, 3, 1, 'do not remove'],
                'fail': [3, 6, 1, None], 'ident': [3, 7, 1, 'flash LED'], 'intf_fail': [2, 0, 1, None], 'locate': [3, 7, 1, 'flash LED'],
                'ups_fail': [2, 2, 1, None], 'warning': [2, 1, 1, None]
            },
            SES_ETC.DISPLAY_ETC : {
                'disp_mode': [1, 1, 2, None], 'disp_char': [2, 7, 16, None], 'fail': [1, 6, 1, None], 'ident': [1, 7, 1, 'flash LED'],
                'locate': [1, 7, 1, 'flash LED']
            },
            SES_ETC.KEY_PAD_ETC : {
                'fail': [1, 6, 1, None], 'ident': [1, 7, 1, 'flash LED'], 'locate': [1, 7, 1, 'flash LED']
            },
            SES_ETC.ENCLOSURE_ETC : {
                'failure_ind': [2, 1, 1, None], 'failure': [3, 1, 1, None], 'ident': [1, 7, 1, 'flash LED'],
                'locate': [1, 7, 1, 'flash LED'], 'pow_cycle': [2, 7, 2, '0: no; 1: start in pow_c_delay minutes; 2: cancel'],
                'pow_c_delay': [2, 5, 6, 'delay in minutes before starting power cycle (max: 60)'],
                'pow_c_duration': [3, 7, 6, '0: power off, restore within 1 minute; <=60: restore within that many minutes; 63: power off, wait for manual power on'],
                'pow_c_time': [2, 7, 6, 'time in minutes remaining until starting power cycle; 0: not scheduled; <=60: scheduled in that many minutes; 63: in zero minutes'],
                'warning': [3, 0, 1, None], 'warning_ind': [2, 0, 1, None]
            },
            SES_ETC.SCSI_PORT_TRAN_ETC : {
                'disable_elm': [3, 4, 1, 'disable port/transceiver'], 'fail': [1, 6, 1, None], 'ident': [1, 7, 1, 'flash LED'],
                'locate': [1, 7, 1, 'flash LED'], 'lol': [3, 1, 1, 'Loss of Link'], 'xmit_fail': [3, 0, 1, 'Transmitter failure']
            },
            SES_ETC.LANGUAGE_ETC : {
                'ident': [1, 7, 1, 'flash LED'], 'language': [2, 7, 16, 'language code'], 'locate': [1, 7, 1, 'flash LED']
            },
            SES_ETC.COMM_PORT_ETC : {
                'disable_elm': [3, 0, 1, 'disable communication port'], 'fail': [1, 7, 1, None], 'ident': [1, 7, 1, 'flash LED'],
                'locate': [1, 7, 1, 'flash LED']
            },
            SES_ETC.VOLT_SENSOR_ETC : {
                'fail': [1, 6, 1, None], 'ident': [1, 7, 1, 'flash LED'], 'locate': [1, 7, 1, 'flash LED'],
                'overvoltage': [1, 1, 1, 'overvoltage'], 'undervoltage': [1, 0, 1, 'undervoltage'],
                'voltage': [2, 7, 16, 'voltage in centivolts']
            },
            SES_ETC.CURR_SENSOR_ETC : {
                'current': [2, 7, 16, 'current in centiamps'], 'fail': [3, 6, 1, None], 'ident': [1, 7, 1, 'flash LED'],
                'locate': [1, 7, 1, 'flash LED'], 'overcurrent': [1, 1, 1, 'overcurrent'],
                'overcurrent_warn': [1, 3, 1, 'overcurrent warning']
            },
            SES_ETC.SCSI_TPORT_ETC : {
                'enable': [3, 0, 1, None], 'fail': [1, 6, 1, None], 'ident': [1, 7, 1, 'flash LED'], 'locate': [1, 7, 1, 'flash LED'],
                'report': [2, 0, 1, None]
            },
            SES_ETC.SCSI_IPORT_ETC : {
                'enable': [3, 0, 1, None], 'fail': [1, 6, 1, None], 'ident': [1, 7, 1, 'flash LED'], 'locate': [1, 7, 1, 'flash LED'],
                'report': [2, 0, 1, None]
            },
            SES_ETC.SIMPLE_SUBENC_ETC : {
                'fail': [1, 6, 1, None], 'ident': [1, 7, 1, 'flash LED'], 'locate': [1, 7, 1, 'flash LED'],
                'short_stat': [3, 7, 8, 'short enclosure status']
            },
            SES_ETC.ARRAY_DEV_ETC : {
                'active': [2, 7, 1, None], 'bypa': [3, 3, 1, 'bypass port A'], 'bypb': [3, 2, 1, 'bypass port B'],
                'conscheck': [1, 4, 1, 'consistency check'], 'devoff': [3, 4, 1, None], 'dnr': [2, 6, 1, 'do not remove'],
                'fault': [3, 5, 1, None], 'hotspare': [1, 5, 1, None], 'ident': [2, 1, 1, 'flash LED'], 'incritarray': [1, 3, 1, None],
                'infailedarray': [1, 2, 1, None], 'insert': [2, 3, 1, None], 'locate': [2, 1, 1, 'flash LED'], 'missing': [2, 4, 1, None],
                'ok': [1, 7, 1, None], 'rebuildremap': [1, 1, 1, None], 'remove': [2, 2, 1, None],
                'rrabort': [1, 0, 1, 'rebuild/remap abort'], 'rsvddevice': [1, 6, 1, 'reserved device']
            },
            SES_ETC.SAS_EXPANDER_ETC : {
                'fail': [1, 6, 1, None], 'ident': [1, 7, 1, 'flash LED'], 'locate': [1, 7, 1, 'flash LED']
            },
            SES_ETC.SAS_CONNECTOR_ETC : {
                'ctr_link': [2, 7, 8, 'connector physical link'], 'ctr_type': [1, 6, 7, 'connector type'], 'fail': [3, 6, 1, None],
                'ident': [1, 7, 1, 'flash LED'], 'locate': [1, 7, 1, 'flash LED'], 'mated': [3, 7, 1, None],
                'overcurrent': [3, 5, 1, None]
            },
            -1 : {
                'disable': [0, 5, 1, None], 'prdfail': [0, 6, 1, 'predict failure'], 'swap': [0, 4, 1, None]
            }
        }
        if index not in acron2loc:
            self.clear_objs()
            raise OSError(-1, "Control not allowed for Element type: " + str(index))
        if cmd not in acron2loc[index]:
            self.clear_objs()
            raise OSError(-1, "Control field " + cmd + " not correct for Element type: " + str(index))
        return acron2loc[index][cmd]

    def get_et_mask(self, index):
        element_dict = {
            SES_ETC.UNSPECIFIED_ETC : [0x40, 0xff, 0xff, 0xff],
            SES_ETC.DEVICE_ETC : [0x40, 0, 0x4e, 0x3c],
            SES_ETC.POWER_SUPPLY_ETC : [0x40, 0x80, 0, 0x60],
            SES_ETC.COOLING_ETC : [0x40, 0x80, 0, 0x60],
            SES_ETC.TEMPERATURE_ETC : [0x40, 0xc0, 0, 0],
            SES_ETC.DOOR_ETC : [0x40, 0xc0, 0, 0x1],
            SES_ETC.AUD_ALARM_ETC : [0x40, 0xc0, 0, 0x5f],
            SES_ETC.ENC_SCELECTR_ETC : [0x40, 0xc0, 0x1, 0],
            SES_ETC.SCC_CELECTR_ETC : [0x40, 0xc0, 0, 0],
            SES_ETC.NV_CACHE_ETC : [0x40, 0xc0, 0, 0],
            SES_ETC.INV_OP_REASON_ETC : [0x40, 0, 0, 0],
            SES_ETC.UI_POWER_SUPPLY_ETC : [0x40, 0, 0, 0xc0],
            SES_ETC.DISPLAY_ETC : [0x40, 0xc0, 0xff, 0xff],
            SES_ETC.KEY_PAD_ETC : [0x40, 0xc3, 0, 0],
            SES_ETC.ENCLOSURE_ETC : [0x40, 0x80, 0, 0xff],
            SES_ETC.SCSI_PORT_TRAN_ETC : [0x40, 0xc0, 0, 0x10],
            SES_ETC.LANGUAGE_ETC : [0x40, 0x80, 0xff, 0xff],
            SES_ETC.COMM_PORT_ETC : [0x40, 0xc0, 0, 0x1],
            SES_ETC.VOLT_SENSOR_ETC : [0x40, 0xc0, 0, 0],
            SES_ETC.CURR_SENSOR_ETC : [0x40, 0xc0, 0, 0],
            SES_ETC.SCSI_TPORT_ETC : [0x40, 0xc0, 0, 0x1],
            SES_ETC.SCSI_IPORT_ETC : [0x40, 0xc0, 0, 0x1],
            SES_ETC.SIMPLE_SUBENC_ETC : [0x40, 0xc0, 0, 0],
            SES_ETC.ARRAY_DEV_ETC : [0x40, 0xff, 0x4e, 0x3c],
            SES_ETC.SAS_EXPANDER_ETC : [0x40, 0xc0, 0, 0],
            SES_ETC.SAS_CONNECTOR_ETC : [0x40, 0x80, 0, 0x40]
        }
        return element_dict[index]

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

    def status(self):
        cdef int len = -1
        cdef int num_ths, desc_len, el, num_dsc, ind, j
        cdef uint32_t ref_gen
        cdef uint8_t * bp
        cdef uint8_t * last_bp
        cdef uint8_t * tc_buff
        cdef char id_buff[18]
        cdef char name_buff[30]
        cdef char ** stat_buff
        cdef char ** desc_buff
        cdef libsgutils.enclosure_info info
        cdef libsgutils.type_desc_hdr_t * tp
        cdef bint invop, infob, noncrit, crit, unrecov
        cdef char * front = id_buff
        cdef char * back = id_buff + sizeof(id_buff)

        enclosure = {
            "id": "",
            "name": "",
            "status": set(),
            "elements": {},
        }

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
            if len < 4:
                self.clear_objs()
                raise OSError(-1, "SES Confgiruation: Response too short.")
            last_bp = self.rsp_buff + len - 1
            bp = self.rsp_buff + 8
            if bp + 3 > last_bp:
                self.clear_objs()
                raise OSError(-1, "SES Confgiruation: Response too short.")
            el = bp[3] + 4
            if el < 40:
                bp += el
            memset(id_buff, 0, sizeof(id_buff))
            for j in range(8):
                front += snprintf(front, back - front, "%02x", bp[4 + j])
            memset(name_buff, 0, sizeof(name_buff))
            snprintf(name_buff, sizeof(name_buff), "%.8s%.16s%.4s", bp + 12, bp + 20, bp + 36)

            self.clear_ptvp()
            self.clear_r_buff()
            num_ths = self.build_tdhs(&ref_gen, &info)
            if num_ths < 0:
                self.clear_objs()
                raise OSError(-1, bytes(self.r_buff, encoding='ascii').decode())
            num_dsc = 0
            for i in range(num_ths):
                num_dsc += (1 + self.desc_hdrs[i].num_elements)
            tc_buff = <uint8_t *> malloc(num_dsc * sizeof(uint8_t))

            self.clear_ptvp()
            self.clear_r_buff()
            if self.get_diagnostic_page(self.ENC_STATUS_DPC, self.rsp_buff, &len) != 0:
                raise OSError(-1, bytes(self.r_buff, encoding='ascii').decode())
            if len < 4:
                self.clear_objs()
                raise OSError(-1, "Enclosure Status: response too short.")
            invop = (self.rsp_buff[1] & 0x10) != 0
            infob = (self.rsp_buff[1] & 0x8) != 0
            noncrit = (self.rsp_buff[1] & 0x4) != 0
            crit = (self.rsp_buff[1] & 0x2) != 0
            unrecov = (self.rsp_buff[1] & 0x1) != 0
            bp = self.rsp_buff + 8
            tp = self.desc_hdrs
            last_bp = self.rsp_buff + len - 1
            ind = 0
            stat_buff = <char**> malloc(num_dsc * sizeof(char *))
            for k in range(0, num_ths):
                if bp + 3 > last_bp:
                    self.clear_objs()
                    raise OSError(-1, "Enclosure Status: response too short.")
                stat_buff[ind] = <char *> malloc(12 * sizeof(char))
                snprintf(stat_buff[ind], 12, "%02x %02x %02x %02x", bp[0], bp[1], bp[2], bp[3])
                ind += 1
                bp += 4
                for j in range (0, tp.num_elements):
                    stat_buff[ind] = <char *> malloc(12 * sizeof(char))
                    snprintf(stat_buff[ind], 12, "%02x %02x %02x %02x", bp[0], bp[1], bp[2], bp[3])
                    ind += 1
                    bp += 4
                tp += 1

            self.clear_ptvp()
            self.clear_r_buff()
            if self.get_diagnostic_page(self.ELEM_DESC_DPC, self.rsp_buff, &len) != 0:
                raise OSError(-1, bytes(self.r_buff, encoding='ascii').decode())
            if len < 8:
                self.clear_objs()
                raise OSError(-1, "Element Descriptor: response too short.")
            bp = self.rsp_buff + 8
            tp = self.desc_hdrs
            last_bp = self.rsp_buff + len - 1
            ind = 0
            desc_buff = <char**> malloc(num_dsc * sizeof(char *))
            for k in range(0, num_ths):
                if bp + 3 > last_bp:
                    self.clear_objs()
                    raise OSError(-1, "Element Descriptor: response too short.")
                desc_len = libsgutils.sg_get_unaligned_be16(bp + 2) + 4
                if desc_len > 4:
                    desc_buff[ind] = <char *> malloc((desc_len - 3) * sizeof(char))
                    snprintf(desc_buff[ind], desc_len - 3, "%.*s", desc_len - 4, bp + 4)
                else:
                    desc_buff[ind] = <char *> malloc(8 * sizeof(char))
                    snprintf(desc_buff[ind], 8, "<empty>")
                tc_buff[ind] = tp.etype
                ind += 1
                bp += desc_len
                for j in range (0, tp.num_elements):
                    desc_len = libsgutils.sg_get_unaligned_be16(bp + 2) + 4
                    if desc_len > 4:
                        desc_buff[ind] = <char *> malloc((desc_len - 3) * sizeof(char))
                        snprintf(desc_buff[ind], desc_len - 3, "%.*s", desc_len - 4, bp + 4)
                    else:
                        desc_buff[ind] = <char *> malloc(8 * sizeof(char))
                        snprintf(desc_buff[ind], 8, "<empty>")
                    tc_buff[ind] = tp.etype
                    ind += 1
                    bp += desc_len
                tp += 1

            with gil:
                enclosure["id"] = bytes(id_buff, encoding='ascii').decode()
                enclosure["name"] = " ".join(bytes(name_buff, encoding='ascii').decode().split())
                if not invop and not infob and not noncrit and not crit and not unrecov:
                    enclosure["status"].add("OK")
                else:
                    if invop:
                        enclosure["status"].add("INVOP")
                    if infob:
                        enclosure["status"].add("INFO")
                    if noncrit:
                        enclosure["status"].add("NON-CRIT")
                    if crit:
                        enclosure["status"].add("CRIT")
                    if unrecov:
                        enclosure["status"].add("UNRECOV")
                elements = {}
                for i in range(num_dsc):
                    type = tc_buff[i]
                    dsc = bytes(desc_buff[i], encoding='ascii').decode()
                    stts = [int(x, 16) for x in bytes(stat_buff[i], encoding='ascii').decode().split()]
                    elements[i] = { "type": type, "descriptor": dsc, "status": stts }
                enclosure["elements"] = elements
            self.clear_objs()
            for i in range(num_dsc):
                free(stat_buff[i])
                free(desc_buff[i])
            free(stat_buff)
            free(desc_buff)
            free(tc_buff)

        return enclosure

    def set_control(self, index, command):
        cdef int len = -1, match = -1
        cdef int k, num_ths, ind_th, ind_indiv, sbyte, sbit, nbits
        cdef uint32_t ref_gen
        cdef uint8_t * bp
        cdef uint8_t * last_bp
        cdef libsgutils.enclosure_info info
        cdef libsgutils.type_desc_hdr_t * tp
        cdef uint64_t value = -1

        if ',' not in index:
            ind_th = 0
            ind_indiv = int(index)
        else:
            ind_th = int(index.split(',')[0])
            ind_indiv = int(index.split(',')[1])

        command = command.split("=")
        if command[0] == "set":
            value = 1
            w = 1
            r = 0
        elif command[0] == "clear":
            value = 0
            w = 1
            r = 0
        elif command[0] == "get":
            r = 1
            w = 0
        else:
            raise OSError(-1, "Control command not correct.")

        with nogil:
            if self.alloc_resp_buffs() != 0:
                self.clear_objs()
                raise OSError(-12, "Out of memory.")
            self.clear_r_buff()
            num_ths = self.build_tdhs(&ref_gen, &info)
            self.clear_ptvp()
            if num_ths < 0:
                self.clear_objs()
                raise OSError(-1, bytes(self.r_buff, encoding='ascii').decode())

            if self.get_diagnostic_page(self.ENC_STATUS_DPC, self.rsp_buff, &len) != 0:
                raise OSError(-1, bytes(self.r_buff, encoding='ascii').decode())
            self.clear_ptvp()

            if len < 8:
                self.clear_objs()
                raise OSError(-1, "Enclosure Control: response too short.")

            if ind_th < 0 or ind_th >= num_ths:
                self.clear_objs()
                raise OSError(-1, "Unable to find Index: " + index)

            last_bp = self.rsp_buff + len - 1
            if libsgutils.sg_get_unaligned_be32(self.rsp_buff + 4) != ref_gen:
                self.clear_objs()
                raise OSError(-1, "Enclosure status changed.")

            bp = self.rsp_buff + 8
            tp = self.desc_hdrs
            for k in range(0, num_ths):
                if bp + 3 > last_bp:
                    self.clear_objs()
                    raise OSError(-1, "Enclosure Control: response too short.")
                bp += 4
                if k == ind_th:
                    if ind_indiv < 0 or ind_indiv >= tp.num_elements:
                        self.clear_objs()
                        raise OSError(-1, "Unable to find Index: " + index)
                    with gil:
                        locs = self.get_acron2locs(tp.etype, command[1])
                        sbyte = locs[0]
                        sbit = locs[1]
                        nbits = locs[2]
                    bp += (4 * ind_indiv)
                    if r:
                        value = libsgutils.sg_get_big_endian(bp + sbyte, sbit, nbits)
                        break
                    elif w:
                        with gil:
                            mask = self.get_et_mask(tp.etype)
                            for i in range(4):
                                bp[i] &= mask[i]
                        libsgutils.sg_set_big_endian(value, bp + sbyte, sbit, nbits)
                        bp[0] |= 0x80
                        len = libsgutils.sg_get_unaligned_be16(self.rsp_buff + 2) + 4
                        value = libsgutils.sg_ll_send_diag_pt(self.ptvp, 0, True, False, False, False , 0, self.rsp_buff, len, False, 0)
                        break
                else:
                    bp += (4 * tp.num_elements)
                tp += 1

            self.clear_objs()
            with gil:
                return value
