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


struct mybrd_device {
	struct request_queue *mybrd_queue;
	struct gendisk *mybrd_disk;
	spinlock_t mybrd_lock;
	// page handling in kernel
	struct radix_tree_root mybrd_pages;
};


static int mybrd_major;
struct mybrd_device *global_mybrd;
#define MYBRD_SIZE_4M 4*1024*1024


//tree 에서 특정 섹터의 데이터를 가지고 있는 페이지를 찾는 함수( 입력- 섹터 번호, 반환- 페이지)
static struct page *mybrd_lookup_page(struct mybrd_device *mybrd,
				      sector_t sector)
{
	pgoff_t idx;
	struct page *p;

	// tree에서 페이지를 찾는 동안 read lock()
	rcu_read_lock();

	//섹터 번호를 가지고 key 값 만들기
	// 1 page = 4096 byte, 1 sector = 512 byte, 1 page = 8 sectors
	// 페이지에 저장되는 최초의 섹터번호를 키 값으로 정함 (섹터번호*512/4096)
	idx = sector >> (PAGE_SHIFT - 9);
	// 특정 키로 페이지 찾기
	p = radix_tree_lookup(&mybrd->mybrd_pages, idx);

	rcu_read_unlock();

	pr_warn("lookup: page-%p index-%d sector-%d\n",
		p, p ? (int)p->index : -1, (int)sector);
	return p;
}

// tree에 페이지 추가
static struct page *mybrd_insert_page(struct mybrd_device *mybrd,
				      sector_t sector)
{
	pgoff_t idx;
	struct page *p;
	gfp_t gfp_flags;

	// 해당 섹터가 tree에 있는지 확인
	p = mybrd_lookup_page(mybrd, sector);
	if (p)
		return p;

	// MUST use _NOIO
	// GFP_NOIO : block i/o 코드에서 메모리 회수가 필요할때 사용. 디스크 io 수행 x
	gfp_flags = GFP_NOIO | __GFP_ZERO;
	p = alloc_page(gfp_flags);
	if (!p)
		return NULL;

	//사전에 tree node 할당
	if (radix_tree_preload(GFP_NOIO)) {
		__free_page(p);
		return NULL;
	}

	/*
	 * According to radix tree API document,
	 * radix_tree_lookup() requires rcu_read_lock(),
	 * but user must ensure the sync of calls for radix_tree_insert().
	 */
	spin_lock(&mybrd->mybrd_lock);

	//섹터 번호로 키 값 구함
	// (sector / 8)
	idx = sector >> (PAGE_SHIFT - 9);
	p->index = idx;

	// radix tree에 페이지 넣기 : root 포인터, key 값(섹터 번호), 페이지 포인터 필요.
	if (radix_tree_insert(&mybrd->mybrd_pages, idx, p)) {
		__free_page(p);
		//tree의 특정 키를 사용하여 페이지 찾기
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

//사용자로부터 커널을 통해 전달된 데이터를 램디스크에 쓰는 함수
static int copy_from_user_to_mybrd(struct mybrd_device *mybrd,
			 struct page *src_page, //데이터가 저장된 페이지
			 int len, // 데이터 크기
			 unsigned int src_offset, // 페이지 내의 데이터 시작 offset
			 sector_t sector) // 커널이 요청한 섹터 번호
{
	struct page *dst_page; 
	void *dst;
	//요청된 섹터 위치
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

	// sector & ( 8 - 1 ) --> 섹터 번호를 8로 나눈 나머지 --> 페이지 안의 섹터의 위치
	// sector % 8 * 512 --> 페이지 안의 섹터 위치의 offset
	target_offset = (sector & (8 - 1)) << 9;

	// 복사할 범위 지정
	// copy = copy data in a page
	copy = min_t(size_t, len, PAGE_SIZE - target_offset);

	// 요청된 섹터를 갖는 페이지 찾기.
	dst_page = mybrd_lookup_page(mybrd, sector);
	// 처음 write 가 발생한 섹터 --> 페이지 없음
	if (!dst_page) {
		// 트리에 페이지 추가
		if (!mybrd_insert_page(mybrd, sector))
			return -ENOSPC;

		// 2개의 페이지에 걸친 데이터라면, 트리에 페이지 하나더 추가
		if (copy < len) {
			if (!mybrd_insert_page(mybrd, sector + (copy >> 9)))
				return -ENOSPC;
		}

		// now it cannot fail
		dst_page = mybrd_lookup_page(mybrd, sector);
		BUG_ON(!dst_page);
	}

	// src_page (커널이 전달한 페이지) 의 메모리 주소
	src = kmap(src_page);
	src += src_offset;

	// dst_page (할당한 페이지) 의 메모리 주소
	dst = kmap(dst_page);
	// 페이지에 있는 데이터 복사
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

//램디스크의 데이터를 사용자에게 보내주는 함수
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
	unsigned long start_time = jiffies;

	pr_warn("start mybrd_make_request_fn: block_device=%p mybrd=%p\n",
		bdev, mybrd);

	//dump_stack();
	
	// print info of bio
	sector = bio->bi_iter.bi_sector;
	end_sector = bio_end_sector(bio);
	rw = bio_rw(bio);
	pr_warn("bio-info: sector=%d end_sector=%d rw=%s\n",
		(int)sector, (int)end_sector, rw == READ ? "READ" : "WRITE");

	generic_start_io_acct(rw, bio_sectors(bio), &mybrd->mybrd_disk->part0);

	//읽기 읽때는 copy_from_mybrd_to_user() 호출
	//쓰기 일대는 copy_from_user_to_mybrd() 호출
	bio_for_each_segment(bvec, bio, iter) {
		unsigned int len = bvec.bv_len;
		struct page *p = bvec.bv_page;
		unsigned int offset = bvec.bv_offset;
		int err;

		pr_warn("segment-info: len=%u p=%p offset=%u\n",
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
			// 읽기 요청시, 드라이버가 가진 데이터를 사용자 페이지로 복사
			// 사용자가 페이지에 접근할 때 메모리로부터 다시 캐시로 데이터가 전송되도록 만듬.
			// 데이터 복사가 끝난 뒤, 캐시 무효화
			flush_dcache_page(page);
		} else if (rw == WRITE) {
			// kernel is going to read data that userspace wrote,
			// so flush-dcache is necessary
			// 쓰기 요청시, 커널은 사용자 페이지 접근
			// 커널이 페이지를 읽기 전에 캐시를 무효화
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

		// 처리된 데이터 만큼 섹터 번호 증가 
		// sector 번호 + (데이터 크기 / 512) 
		sector = sector + (len >> 9);
	}
		
	bio_endio(bio);

	generic_end_io_acct(rw, &mybrd->mybrd_disk->part0, start_time);
		
	pr_warn("end mybrd_make_request_fn\n");
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


static struct mybrd_device *mybrd_alloc(void)
{
	struct mybrd_device *mybrd;
	struct request_queue *rq;
	struct gendisk *disk;

	pr_warn("start mybrd_alloc\n");

	/*
	 * 1st: mybrd_device object
	 */
	mybrd = kzalloc(sizeof(*mybrd), GFP_KERNEL);
	if (!mybrd)
		goto out;

	spin_lock_init(&mybrd->mybrd_lock);
	// radix_tree_root 구조체 초기화: radix tree의 root
	INIT_RADIX_TREE(&mybrd->mybrd_pages, GFP_ATOMIC);
	pr_warn("create mybrd:%p\n", mybrd);

	/*
	 * 2nd: request-queue object
	 */
	rq = mybrd->mybrd_queue = blk_alloc_queue_node(GFP_KERNEL, NUMA_NO_NODE);
	if (!rq)
		goto out_free_brd;

	blk_queue_make_request(rq, mybrd_make_request_fn);
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
	disk->queue = rq;
	disk->flags = GENHD_FL_EXT_DEVT;
	strncpy(disk->disk_name, "mybrd", strlen("mybrd"));
	set_capacity(disk, MYBRD_SIZE_4M >> 9);

	// start IO
	add_disk(disk);
	pr_warn("end mybrd_alloc\n");
	
	return mybrd;

out_free_queue:
	blk_cleanup_queue(rq);
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


