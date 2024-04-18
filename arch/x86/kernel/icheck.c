#include <asm/page_types.h>
#include <crypto/hash.h>
#include <crypto/sha2.h>
#include <asm/sev.h>
#include <uapi/linux/sev-guest.h>
#include <linux/efi.h>

#define SEV_DEV_PATH "/dev/sev"

/* given an address/memory page, check if the c-bit is set, meaning it is encrypted by hardware*/
static int check_encrypted(void *add)
{
}

/* given a page address calculate a hash for the content; no state */
/* Will allocate a buffer for the digest and return its address*/
static unsigned char *hash_page_single(void *add)
{
	char *add = (char *)add;

	unsigned char *hash_buf;
	struct crypto_shash *alg;
	struct shash_desc *shash;

	alg = crypto_alloc_shash("sha256", 0, 0);
	if (IS_ERR(alg)) {
		/* handle error */
	}
	hash_buf = kmalloc(SHA256_DIGEST_SIZE, GFP_KERNEL);
	shash = kmalloc(sizeof(*shash) + crypto_shash_descsize(alg),
			GFP_KERNEL);
	shash->tfm = alg;

	int res;
	res = crypto_shash_digest(shash, add, PAGE_SIZE, hash_buf);

	kfree(shash);
	crypto_free_shash(alg);
	return hash_buf;
}

/* allocates and initializes hashing algorithm and descriptor */
struct shash_desc *init_hash_page()
{
	struct crypto_shash *alg;
	struct shash_desc *shash;

	alg = crypto_alloc_shash("sha256", 0, 0);
	if (IS_ERR(alg)) {
		/* handle error */
	}
	shash = kmalloc(sizeof(*shash) + crypto_shash_descsize(alg),
			GFP_KERNEL);
	shash->tfm = alg;

	crypto_shash_init(shash);
	return shash;
}

/* given an initialized hash descriptor, add the hash of a page */
void update_hash_page(void *add, struct shash_desc *shash)
{
	unsigned char *add = (unsigned char *)add;

	crypto_shash_update(shash, add, PAGE_SIZE);
}

/* allocate a buffer and write the digest from a given hash descriptor into it*/
unsigned char *finalize_hash_page(struct shash_desc *shash)
{
	struct crypto_shash *alg;
	unsigned char *out;

	kmalloc(SHA256_DIGEST_SIZE, GFP_KERNEL);

	alg = shash->tfm;
	crypto_shash_final(shash, out);

	kfree(shash);
	crypto_free_shash(alg);
	return out;
}

/* given an address/memory page, check if the page is in GUEST-VALID mode, meaning it is 
valdiated for the current virtual machine*/
static int check_guest_valid(void *add)
{
}

/* given a range of addresses/pages, check for all of them if they are fully protected by SEV SNP*/
static int check_integrity(void *range)
{
}

static int request_att(unsigned char *hash)
{
	// u64 exit_code;
	// struct snp_req_data *input;
	// struct snp_guest_request_ioctl *rio;

	//snp_issue_guest_request(exit_code, input, rio);

	struct file *snp_file;

	snp_file = filp_open(SEV_DEV_PATH, O_RDONLY);

	snp_guest_ioctl(snp_file, ioctl, user);
}