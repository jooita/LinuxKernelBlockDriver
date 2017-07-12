/*
 * Ram backed block device driver.
 *
 * Copyright (C) 2007 Nick Piggin
 * Copyright (C) 2007 Novell Inc.
 *
 * Parts derived from drivers/block/rd.c, and drivers/block/loop.c, copyright
 * of their respective owners.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/major.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/highmem.h>
#include <linux/mutex.h>
#include <linux/radix-tree.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include <linux/blk-mq.h>
#include <linux/nodemask.h>

#ifdef pr_warn
#undef pr_warn
#endif
#define pr_warn(fmt, arg...) printk(KERN_WARNING "mybrd: "fmt, ##arg)

MODULE_LICENSE("GPL");

enum {
	MYBRD_Q_BIO		= 0, // process IO in bio by bio
	MYBRD_Q_RQ		= 1, // IO in request base
};

enum {
	MYBRD_IRQ_NONE		= 0,
	MYBRD_IRQ_SOFTIRQ	= 1,
};

struct mybrd_device {
	struct request_queue *mybrd_queue;
	struct gendisk *mybrd_disk;
	spinlock_t mybrd_lock;
	spinlock_t mybrd_queue_lock;
	struct radix_tree_root mybrd_pages;
};


static int queue_mode = MYBRD_Q_RQ;
static int irqmode = MYBRD_IRQ_SOFTIRQ;
static int mybrd_major;
struct mybrd_device *global_mybrd;
#define MYBRD_SIZE_1M 4*1024*1024


static struct page *mybrd_lookup_page(struct mybrd_device *mybrd,
				      sector_t sector)
{
	pgoff_t idx;
	struct page *p;

	rcu_read_lock(); // why rcu-read-lock?

	// 9 = SECTOR_SHIFT
	idx = sector >> (PAGE_SHIFT - 9);
	p = radix_tree_lookup(&mybrd->mybrd_pages, idx);

	rcu_read_unlock();

	pr_warn("lookup: page-%p index-%d sector-%d\n",
		p, p ? (int)p->index : -1, (int)sector);
	return p;
}

static struct page *mybrd_insert_page(struct mybrd_device *mybrd,
				      sector_t sector)
{
	pgoff_t idx;
	struct page *p;
	gfp_t gfp_flags;

	p = mybrd_lookup_page(mybrd, sector);
	if (p)
		return p;

	// must use _NOIO
	gfp_flags = GFP_NOIO | __GFP_ZERO;
	p = alloc_page(gfp_flags);
	if (!p)
		return NULL;

	if (radix_tree_preload(GFP_NOIO)) {
		__free_page(p);
		return NULL;
	}

	// According to radix tree API document,
	// radix_tree_lookup() requires rcu_read_lock(),
	// but user must ensure the sync of calls to radix_tree_insert().
	spin_lock(&mybrd->mybrd_lock);

	// #sector -> #page
	// one page can store 8-sectors
	idx = sector >> (PAGE_SHIFT - 9);
	p->index = idx;

	if (radix_tree_insert(&mybrd->mybrd_pages, idx, p)) {
		__free_page(p);
		p = radix_tree_lookup(&mybrd->mybrd_pages, idx);
		pr_warn("failed to insert page: duplicated=%d\n",
			(int)idx);
	} else {
		pr_warn("insert: page-%p index=%d sector-%d\n",
			p, (int)idx, (int)sector);
	}

	spin_unlock(&mybrd->mybrd_lock);

	radix_tree_preload_end();
	
	return p;
}

static void show_data(unsigned char *ptr)
{
	pr_warn("%x %x %x %x %x %x %x %x\n",
		ptr[0], ptr[1], ptr[2], ptr[3],
		ptr[4],	ptr[5],	ptr[6], ptr[7]);
}

static int copy_from_user_to_mybrd(struct mybrd_device *mybrd,
			 struct page *src_page,
			 int len,
			 unsigned int src_offset,
			 sector_t sector)
{
	struct page *dst_page;
	void *dst;
	unsigned int target_offset;
	size_t copy;
	void *src;

	// sectors can be stored across two pages
	// 8 = one page can have 8-sectors
	// target_offset = sector * 512(sector-size) = target_offset in a page
	// eg) sector = 123, size=4096
	// page1 <- sector120 ~ sector127
	// page2 <- sector128 ~ sector136
	// store 512*5-bytes at page1 (sector 123~127)
	// store 512*3-bytes at page2 (sector 128~130)
	// page1->index = 120, page2->index = 128

	target_offset = (sector & (8 - 1)) << 9;
	// copy = copy data in a page
	copy = min_t(size_t, len, PAGE_SIZE - target_offset);

	dst_page = mybrd_lookup_page(mybrd, sector);
	if (!dst_page) {
		// First added data, need to make space to store data

		// insert the first page
		if (!mybrd_insert_page(mybrd, sector))
		    return -ENOSPC;

		if (copy < len) {
			if (!mybrd_insert_page(mybrd, sector + (copy >> 9)))
				return -ENOSPC;
		}

		// now it cannot fail
		dst_page = mybrd_lookup_page(mybrd, sector);
		BUG_ON(!dst_page);
	}

	src = kmap(src_page);
	src += src_offset;

	dst = kmap(dst_page);
	memcpy(dst + target_offset, src, copy);
	kunmap(dst_page);

	pr_warn("copy: %p <- %p (%d-bytes)\n", dst + target_offset, src, (int)copy);
	show_data(dst+target_offset);
	show_data(src);
	
	// copy next page
	if (copy < len) {
		src += copy;
		sector += (copy >> 9);
		copy = len - copy;
		dst_page = mybrd_lookup_page(mybrd, sector);
		BUG_ON(!dst_page);

		dst = kmap(dst_page); // next page

		// dst: copy data at the first address of the page
		memcpy(dst, src, copy);
		kunmap(dst_page);

		pr_warn("copy: %p <- %p (%d-bytes)\n", dst + target_offset, src, (int)copy);
		show_data(dst);
		show_data(src);
	}
	kunmap(src_page);

	return 0;
}

static int copy_from_mybrd_to_user(struct mybrd_device *mybrd,
				   struct page *dst_page,
				   int len,
				   unsigned int dst_offset,
				   sector_t sector)
{
	struct page *src_page;
	void *src;
	size_t copy;
	void *dst;
	unsigned int src_offset;

	src_offset = (sector & 0x7) << 9;
	copy = min_t(size_t, len, PAGE_SIZE - src_offset);

	dst = kmap(dst_page);
	dst += dst_offset;
	
	src_page = mybrd_lookup_page(mybrd, sector);
	if (src_page) {
		src = kmap_atomic(src_page);
		src += src_offset;
		memcpy(dst, src, copy);
		kunmap_atomic(src);

		pr_warn("copy: %p <- %p (%d-bytes)\n", dst, src, (int)copy);
		show_data(dst);
		show_data(src);
	} else {
		memset(dst, 0, copy);
		pr_warn("copy: %p <- 0 (%d-bytes)\n", dst, (int)copy);
		show_data(dst);
	}

	kunmap(dst_page);
	return 0;
}

static blk_qc_t mybrd_make_request_fn(struct request_queue *q, struct bio *bio)
{
	struct block_device *bdev = bio->bi_bdev;
	struct mybrd_device *mybrd = bdev->bd_disk->private_data;
	int rw;
	struct bio_vec bvec;
	sector_t sector;
	sector_t end_sector;
	struct bvec_iter iter;

	pr_warn("start mybrd_make_request_fn: block_device=%p mybrd=%p\n",
		bdev, mybrd);

	//dump_stack();
	
	// print info of bio
	sector = bio->bi_iter.bi_sector;
	end_sector = bio_end_sector(bio);
	rw = bio_rw(bio);
	pr_warn("bio-info: sector=%d end_sector=%d rw=%s\n",
		(int)sector, (int)end_sector, rw == READ ? "READ" : "WRITE");

	// ffffffff81187890 t end_bio_bh_io_sync
	pr_warn("bio-info: end-io=%p\n", bio->bi_end_io);


	bio_for_each_segment(bvec, bio, iter) {
		unsigned int len = bvec.bv_len;
		struct page *p = bvec.bv_page;
		unsigned int offset = bvec.bv_offset;
		int err;

		pr_warn("bio-info: len=%u p=%p offset=%u\n",
			len, p, offset);

		// The reason of flush-dcache
		// https://patchwork.kernel.org/patch/2742
		// You have to call fluch_dcache_page() in two situations,
		// when the kernel is going to read some data that userspace wrote, *and*
		// when userspace is going to read some data that the kernel wrote.
		
		if (rw == READ || rw == READA) {
			// kernel write data from kernelspace into userspace
			err = copy_from_mybrd_to_user(mybrd,
						      p,
						      len,
						      offset,
						      sector);
			if (err)
				goto io_error;

			// userspace is going to read data that the kernel just wrote
			// so flush-dcache is necessary
			flush_dcache_page(page);
		} else if (rw == WRITE) {
			// kernel is going to read data that userspace wrote,
			// so flush-dcache is necessary
			flush_dcache_page(page);
			err = copy_from_user_to_mybrd(mybrd,
						      p,
						      len,
						      offset,
						      sector);
			if (err)
				goto io_error;
		} else {
			pr_warn("rw is not READ/WRITE\n");
			goto io_error;
		}

		if (err)
			goto io_error;

		sector = sector + (len >> 9);
	}
		
	// when disk is added, make_request is called..why??
	
	bio_endio(bio);
	
	pr_warn("end mybrd_make_request_fn\n");
	// no cookie
	return BLK_QC_T_NONE;
io_error:
	bio_io_error(bio);
	return BLK_QC_T_NONE;
}


static int mybrd_ioctl(struct block_device *bdev, fmode_t mode,
			unsigned int cmd, unsigned long arg)
{
	int error = 0;
	pr_warn("start mybrd_ioctl\n");

	pr_warn("end mybrd_ioctl\n");
	return error;
}

static const struct block_device_operations mybrd_fops = {
	.owner =		THIS_MODULE,
	.ioctl =		mybrd_ioctl,
};

static int mybrd_prep_rq_fn(struct request_queue *q, struct request *req)
{
	struct mybrd_device *mybrd = q->queuedata;

	pr_warn("start prep_rq_fn: q=%p req=%p\n", q, req);
	//dump_stack();
	
	if (req->special) {
		return BLKPREP_KILL;
	}

	req->special = mybrd;

	pr_warn("prep-request: len=%d disk=%p start_time=%lu end_io=%p\n",
		(int)req->__data_len, req->rq_disk,
		req->start_time, req->end_io);
	pr_warn("end prep_rq_fn\n");
	return BLKPREP_OK;
}

static int _mybrd_request_fn(struct request *req)
{
	struct bio_vec bvec;
	struct req_iterator iter;
	unsigned int len;
	struct page *p;
	unsigned int offset;
	sector_t sector;
	struct mybrd_device *mybrd = req->q->queuedata;
	int err;

	if (req->special != req->q->queuedata) {
		pr_warn("\nunknown request error\n\n");
		goto io_error;
	}
	
	//request에서 처리해야할 첫번째 섹터 번호 반환
	sector = blk_rq_pos(req); // initial sector

	//request에서 segment를 하나씩 가져와 처리
	rq_for_each_segment(bvec, req, iter) {
		len = bvec.bv_len;
		p = bvec.bv_page;
		offset = bvec.bv_offset;
		pr_warn("    sector=%d segment-info: len=%u p=%p offset=%u\n",
			(int)sector, len, p, offset);

		if (rq_data_dir(req)) { // WRITE
			flush_dcache_page(page);
			err = copy_from_user_to_mybrd(mybrd,
						      p,
						      len,
						      offset,
						      sector);
			if (err) {
				pr_warn("    request_fn: failed to"
					"write sector\n");
				goto io_error;
			}
		} else { // READ
			err = copy_from_mybrd_to_user(mybrd,
						      p,
						      len,
						      offset,
						      sector);
			if (err) {
				pr_warn("    request_fn: failed to"
					"read sector\n");
				goto io_error;
			}
			flush_dcache_page(page);
		}
		sector += (len >> 9);
	}
	return 0;
io_error:
	return -EIO;
}

//for softIRQ
// request의 queuelist를 초기화하여 queue로부터 request 분리
static void mybrd_softirq_done_fn(struct request *req)
{
	int err;
	pr_warn("start softirq_done_fn: complete delayed request: %p", req);
	list_del_init(&req->queuelist);
	// 하나의 request 처리
	err = _mybrd_request_fn(req);
	blk_end_request_all(req, err);
	pr_warn("end softirq_done_fn\n");
}

static void mybrd_request_fn(struct request_queue *q)
{
	struct request *req;
	int err = 0;

	pr_warn("start request_fn: q=%p irqmode=%d\n", q, irqmode);
	//dump_stack();

	//request queue에서 하나의 request를 가져옴
	while ((req = blk_fetch_request(q)) != NULL) {
		spin_unlock_irq(q->queue_lock);

		pr_warn("  fetch-request: req=%p len=%d rw=%s\n",
			req, (int)blk_rq_bytes(req),
			rq_data_dir(req) ? "WRITE":"READ");
		
		switch (irqmode) {
		case MYBRD_IRQ_NONE:
			err = _mybrd_request_fn(req);
			//request 처리의 끝을 커널에게 알림
			blk_end_request_all(req, err);
			break;

		//for softIRQ
		case MYBRD_IRQ_SOFTIRQ:
			// pass request into per-cpu list blk_cpu_done
			// softirq_done_fn will be called for each request
			//
			// blk_cpu_done : per-cpu 리스트, BLOCK_SOFTIRQ 등록
			// 해당 request를 blk_cpu_done 리스트에 추가
			blk_complete_request(req);
			break;
		}

		spin_lock_irq(q->queue_lock);
	}
	pr_warn("end request_fn\n");
}

static struct mybrd_device *mybrd_alloc(void)
{
	struct mybrd_device *mybrd;
	struct gendisk *disk;
	struct request_queue *rq;

	pr_warn("start mybrd_alloc\n");

	/*
	 * 1st: mybrd_device object
	 */
	mybrd = kzalloc(sizeof(*mybrd), GFP_KERNEL);
	if (!mybrd)
		goto out;

	spin_lock_init(&mybrd->mybrd_lock);
	spin_lock_init(&mybrd->mybrd_queue_lock);
	INIT_RADIX_TREE(&mybrd->mybrd_pages, GFP_ATOMIC);

	if (queue_mode == MYBRD_Q_BIO) {
		//bio 단위로 IO 정보를 전달하는 queue 생성
		rq = mybrd->mybrd_queue = blk_alloc_queue_node(GFP_KERNEL,
							       NUMA_NO_NODE);
		if (!mybrd->mybrd_queue)
			goto out_free_brd;
		blk_queue_make_request(mybrd->mybrd_queue, mybrd_make_request_fn);
	} else if (queue_mode == MYBRD_Q_RQ) {
		//request 단위로 IO 정보를 전달하는 IO scheduler를 포함한 queue 생성
		rq = mybrd->mybrd_queue = blk_init_queue_node(mybrd_request_fn,
							      &mybrd->mybrd_queue_lock,
							      NUMA_NO_NODE);
		if (!mybrd->mybrd_queue) {
			pr_warn("failed to create RQ-queue\n");
			goto out_free_brd;
		}
		blk_queue_prep_rq(mybrd->mybrd_queue, mybrd_prep_rq_fn);


		//for softIRQ
		if (irqmode == MYBRD_IRQ_SOFTIRQ)
			blk_queue_softirq_done(mybrd->mybrd_queue,
					       mybrd_softirq_done_fn);
	}
	pr_warn("create queue: mybrd-%p queue-mode-%d rq=%p\n",
		mybrd, queue_mode, rq);

	rq->queuedata = mybrd;
	blk_queue_max_hw_sectors(rq, 1024);
	blk_queue_bounce_limit(rq, BLK_BOUNCE_ANY);
	blk_queue_physical_block_size(rq, PAGE_SIZE);
	blk_queue_logical_block_size(rq, PAGE_SIZE);
	rq->limits.discard_granularity = PAGE_SIZE;
	blk_queue_max_discard_sectors(rq, UINT_MAX);
	rq->limits.discard_zeroes_data = 1;
	queue_flag_set_unlocked(QUEUE_FLAG_DISCARD, rq);

	/*
	 * 3rd: gendisk object
	 */
	disk = mybrd->mybrd_disk = alloc_disk(1);
	if (!disk)
		goto out_free_queue;

	disk->major = mybrd_major;
	disk->first_minor = 111;
	disk->fops = &mybrd_fops;
	disk->private_data = mybrd;
	disk->queue = mybrd->mybrd_queue;
	disk->flags = GENHD_FL_EXT_DEVT;
	strncpy(disk->disk_name, "mybrd", strlen("mybrd"));
	set_capacity(disk, MYBRD_SIZE_1M >> 9);

	// start IO
	add_disk(disk);
	pr_warn("end mybrd_alloc\n");
	
	return mybrd;
out_free_queue:
	blk_cleanup_queue(mybrd->mybrd_queue);

out_free_brd:
	kfree(mybrd);
out:
	return NULL;
}

static void mybrd_free(struct mybrd_device *mybrd)
{
	blk_cleanup_queue(global_mybrd->mybrd_queue);
	kfree(global_mybrd);
}

static int __init mybrd_init(void)
{
	pr_warn("\n\n\nmybrd: module loaded\n\n\n\n");

	mybrd_major = register_blkdev(mybrd_major, "my-ramdisk");
	if (mybrd_major < 0)
		return mybrd_major;

	pr_warn("mybrd major=%d\n", mybrd_major);
	global_mybrd = mybrd_alloc();
	if (!global_mybrd) {
		pr_warn("failed to initialize mybrd\n");
		unregister_blkdev(mybrd_major, "my-ramdisk");
		return -1;
	}
	pr_warn("global-mybrd=%p\n", global_mybrd);

	return 0;
}

static void __exit mybrd_exit(void)
{
	mybrd_free(global_mybrd);
	unregister_blkdev(mybrd_major, "my-ramdisk");
	
	pr_warn("brd: module unloaded\n");
}

module_init(mybrd_init);
module_exit(mybrd_exit);
