#include <linux/socket.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <rdma/ib_verbs.h>
#include <rdma/rdma_cm.h>

#define DRV_NAME	"isert"
#define PFX		DRV_NAME ": "

#define isert_dbg(fmt, arg...)				 \
	do {						 \
		if (unlikely(isert_debug_level > 2))	 \
			printk(KERN_DEBUG PFX "%s: " fmt,\
				__func__ , ## arg);	 \
	} while (0)

#define isert_warn(fmt, arg...)				\
	do {						\
		if (unlikely(isert_debug_level > 0))	\
			pr_warn(PFX "%s: " fmt,         \
				__func__ , ## arg);	\
	} while (0)

#define isert_info(fmt, arg...)				\
	do {						\
		if (unlikely(isert_debug_level > 1))	\
			pr_info(PFX "%s: " fmt,         \
				__func__ , ## arg);	\
	} while (0)

#define isert_err(fmt, arg...) \
	pr_err(PFX "%s: " fmt, __func__ , ## arg)

#define ISCSI_ISER_SG_TABLESIZE		256
#define ISER_FASTREG_LI_WRID		0xffffffffffffffffULL
#define ISER_BEACON_WRID               0xfffffffffffffffeULL

enum iser_conn_state {
	ISER_CONN_INIT,
	ISER_CONN_UP,
	ISER_CONN_FULL_FEATURE,
	ISER_CONN_TERMINATING,
	ISER_CONN_DOWN,
};

struct iser_rx_desc {
	struct iser_hdr iser_header;
	struct iscsi_hdr iscsi_header;
	char		data[ISER_RECV_DATA_SEG_LEN];
	u64		dma_addr;
	struct ib_sge	rx_sg;
	char		pad[ISER_RX_PAD_SIZE];
} __packed;

struct iser_tx_desc {
	struct iser_hdr iser_header;
	struct iscsi_hdr iscsi_header;
	u64		dma_addr;
	struct ib_sge	tx_sg[2];
	int		num_sge;
	struct isert_cmd *isert_cmd;
	struct ib_send_wr send_wr;
} __packed;

struct isert_fr_desc {
	struct list_head		list;
	struct ib_mr		       *data_mr;
	struct ib_sge			data_sge;
	struct ib_reg_wr		data_reg_wr;
	struct ib_mr		       *prot_mr;
	struct ib_sge			prot_sge;
	struct ib_reg_wr		prot_reg_wr;
	struct ib_mr		       *sig_mr;
	struct ib_sig_handover_wr	sig_reg_wr;
	struct ib_sig_attrs		sig_attrs;
	u8				data_mr_valid:1;
	u8				prot_mr_valid:1;
	u8				sig_mr_valid:1;
	u8				sig_protected:1;
};

struct isert_data_buf {
	struct scatterlist     *sg;
	int			nents;
	u32			sg_off;
	u32			len;
	u32			offset;
	unsigned int		dma_nents;
	enum dma_data_direction dma_dir;
};

struct isert_rdma_ctx {
	struct ib_sge			*sges;
	int				nsge;
	struct ib_rdma_wr		*rdmas;
	int				nrdmas;
	struct ib_send_wr		*first_wr;
	struct ib_send_wr		*last_wr;
	int				nsge_per_rdma;
	enum dma_data_direction 	dma_dir;
	u32				data_reg_offset;
	u32				prot_reg_offset;
	u32				ref_tag_offset;
	struct isert_data_buf		data;
	struct isert_data_buf		prot;
	struct list_head		fr_list;
};

struct isert_cmd {
	uint32_t		read_stag;
	uint32_t		write_stag;
	uint64_t		read_va;
	uint64_t		write_va;
	u64			pdu_buf_dma;
	u32			pdu_buf_len;
	struct isert_rdma_ctx	rdma_ctx;
	struct isert_conn	*conn;
	struct iscsi_cmd	*iscsi_cmd;
	struct iser_tx_desc	tx_desc;
	struct iser_rx_desc	*rx_desc;
	struct work_struct	comp_work;
	struct scatterlist	sg;
};

struct isert_device;

struct isert_conn {
	enum iser_conn_state	state;
	int			post_recv_buf_count;
	u32			responder_resources;
	u32			initiator_depth;
	bool			pi_support;
	char			*login_buf;
	char			*login_req_buf;
	char			*login_rsp_buf;
	u64			login_req_dma;
	int			login_req_len;
	u64			login_rsp_dma;
	struct iser_rx_desc	*rx_descs;
	struct ib_recv_wr	rx_wr[ISERT_QP_MAX_RECV_DTOS];
	struct iscsi_conn	*conn;
	struct list_head	node;
	struct completion	login_comp;
	struct completion	login_req_comp;
	struct iser_tx_desc	login_tx_desc;
	struct rdma_cm_id	*cm_id;
	struct ib_qp		*qp;
	struct isert_device	*device;
	struct mutex		mutex;
	struct completion	wait;
	struct completion	wait_comp_err;
	struct kref		kref;
	struct list_head	fr_pool;
	int			fr_pool_size;
	/* lock to protect fastreg pool */
	spinlock_t		pool_lock;
	struct work_struct	release_work;
	struct ib_recv_wr       beacon;
	bool                    logout_posted;
};

#define ISERT_MAX_CQ 64

/**
 * struct isert_comp - iSER completion context
 *
 * @device:     pointer to device handle
 * @cq:         completion queue
 * @wcs:        work completion array
 * @active_qps: Number of active QPs attached
 *              to completion context
 * @work:       completion work handle
 */
struct isert_comp {
	struct isert_device     *device;
	struct ib_cq		*cq;
	struct ib_wc		 wcs[16];
	int                      active_qps;
	struct work_struct	 work;
};

struct isert_device {
	struct ib_device	*ib_device;
	struct ib_pd		*pd;
	struct isert_comp	*comps;
	int                     comps_used;
	bool			pi_capable;
	int			max_sge_rd;
	int			max_sge_wr;
	unsigned int		max_reg_pages;
	bool			register_rdma_reads;
	int			rdma_read_access;
	int			refcount;
	struct list_head	dev_node;
	struct ib_device_attr	dev_attr;
};

struct isert_np {
	struct iscsi_np         *np;
	struct semaphore	sem;
	struct rdma_cm_id	*cm_id;
	struct mutex		mutex;
	struct list_head	accepted;
	struct list_head	pending;
};

static inline void
isert_chain_wr(struct isert_rdma_ctx *ctx, struct ib_send_wr *wr)
{
	if (!ctx->first_wr)
		ctx->first_wr = wr;

	if (ctx->last_wr)
		ctx->last_wr->next = wr;

	ctx->last_wr = wr;
	wr->next = NULL;
}

static inline bool
isert_prot_cmd(struct isert_cmd *isert_cmd)
{
	return (isert_cmd->conn->pi_support &&
		isert_cmd->iscsi_cmd->se_cmd.prot_op != TARGET_PROT_NORMAL);
}

static inline bool
isert_cmd_reg_on_rdma_read(struct isert_cmd *isert_cmd)
{
	return (isert_cmd->rdma_ctx.dma_dir == DMA_FROM_DEVICE &&
	        isert_cmd->conn->device->register_rdma_reads);
}

static inline bool
isert_cmd_reg_needed(struct isert_cmd *isert_cmd)
{
	return (isert_prot_cmd(isert_cmd) ||
		isert_cmd_reg_on_rdma_read(isert_cmd));
}
