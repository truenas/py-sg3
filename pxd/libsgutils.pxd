from libc.stdint cimport uint8_t, uint16_t, uint32_t

cdef struct type_desc_hdr_t:
    uint8_t etype
    uint8_t num_elements
    uint8_t se_id
    uint8_t txt_len

cdef struct enclosure_info:
    int have_info
    int rel_esp_id
    int num_esp
    uint8_t enc_log_id[8]
    uint8_t enc_vendor_id[8]
    uint8_t product_id[16]
    uint8_t product_rev_level[4]

cdef extern from "scsi/sg_pt_nvme.h":

    cdef struct sg_sntl_dev_state_t:
        unsigned char scsi_dsense
        unsigned char enclosure_override
        unsigned char pdt
        unsigned char enc_serv
        unsigned char id_ctl253

cdef extern from "scsi/sg_pt_linux.h" nogil:

    cdef struct sg_io_v4:
        int guard
        unsigned int protocol
        unsigned int subprotocol
        unsigned int request_len
        unsigned long long request
        unsigned long long request_tag
        unsigned int request_attr
        unsigned int request_priority
        unsigned int request_extra
        unsigned int max_response_len
        unsigned long long response
        unsigned int dout_iovec_count
        unsigned int dout_xfer_len
        unsigned int din_iovec_count
        unsigned int din_xfer_len
        unsigned long long dout_xferp
        unsigned long long din_xferp
        unsigned int timeout
        unsigned int flags
        unsigned long long usr_ptr
        unsigned int spare_in
        unsigned int driver_status
        unsigned int transport_status
        unsigned int device_status
        unsigned int retry_delay
        unsigned int info
        unsigned int duration
        unsigned int response_len
        int din_resid
        int dout_resid
        unsigned long long generated_tag
        unsigned int spare_out
        unsigned int padding

    cdef struct sg_pt_linux_scsi:
        sg_io_v4 io_hdr
        bint is_sg
        bint is_bsg
        bint is_nvme
        bint nvme_direct
        bint nvme_stat_dnr
        bint nvme_stat_more
        bint mdxfer_out
        int dev_fd
        int in_err
        int os_err
        int sg_version
        unsigned int nvme_nsid
        unsigned int nvme_result
        unsigned int nvme_status
        unsigned int mdxfer_len
        sg_sntl_dev_state_t dev_stat
        void * mdxferp
        unsigned char * nvme_id_ctlp
        unsigned char * free_nvme_id_ctlp
        unsigned char tmf_request[4]

    cdef struct sg_pt_base:
        sg_pt_linux_scsi impl

    void clear_scsi_pt_obj(sg_pt_base *)

cdef extern from "scsi/sg_cmds.h" nogil:

    int sg_cmds_open_device(const char *, bint, int)
    int sg_cmds_close_device(int)
    int sg_ll_inquiry_pt(sg_pt_base *, bint, int, void *, int, int, int *, bint, int)
    int sg_ll_receive_diag_pt(sg_pt_base *, bint, int, void *, int, int, int *, bint, int)

cdef extern from "scsi/sg_pt.h" nogil:

    sg_pt_base * construct_scsi_pt_obj_with_fd(int, int)
    void destruct_scsi_pt_obj(sg_pt_base *)

cdef extern from "scsi/sg_lib.h" nogil:

    unsigned char * sg_memalign(unsigned int, unsigned int, unsigned char **, bint)
    char *sg_get_pdt_str(int, int, char *)

cdef extern from "scsi/sg_unaligned.h" nogil:

    uint16_t sg_get_unaligned_be16(const void *)
    uint32_t sg_get_unaligned_be32(const void *)
