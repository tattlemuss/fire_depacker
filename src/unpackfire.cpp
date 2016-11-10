/*

*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <memory.h>
#include <assert.h>

/*
	Wraps unpacker state to ensure safe buffering etc.
*/
struct Context
{
	const uint8_t*	src;		/* current source data input */
	uint8_t			cmd;		/* current command byte */
	uint8_t*		dst;		/* One greater than next byte to write */
	const uint8_t*	srcbase;	/* Base address to depack from (after skipping header) */
	uint8_t*		dstbase;	/* Base address to depack to */
};

void dbgout(uint8_t val)
{
	if (val >= ' ' && val < 128)
		printf("->'%c'\n", val);
	else
		printf("->0x%x\n", val);
}

uint32_t fire_get_dword(const unsigned char *p)
{
  uint32_t res;
  res=*p++;
  res<<=8;
  res+=*p++;
  res<<=8;
  res+=*p++;
  res<<=8;
  res+=*p;
  return res;
}

int fire_header(const unsigned char *src)
{ /* returns 0 if no Fire header was found */
  return (fire_get_dword(src)==0x46495245);
}

uint32_t fire_packedsize(const unsigned char *src)
{ /* returns packed size of Fire packed data (+12 -> including headers!) */
  return (uint32_t) fire_get_dword(src+4);
}

uint32_t fire_origsize(const unsigned char *src)
{ /* returns original size of Fire packed data */
  return (uint32_t) fire_get_dword(src+8);
}

int fire_is_finished(const Context* ctx)
{
	return (ctx->dst == ctx->dstbase);
}

void fire_output(Context* ctx, uint8_t val)
{
	/* Protect against buffer overwrite */
	if (!fire_is_finished(ctx))
	{
		--(ctx->dst);
		*(ctx->dst) = val;
		dbgout(val);
	}
}

uint8_t get_bit(Context* ctx)
{
	// Protect against input overrun
	if (ctx->src == ctx->srcbase)
		return 0;
		
	// Bit is the top
	printf("\t\t\t\t\tstarting cmd byte %x\n", ctx->cmd);

	// 	ADD.B	D7,D7
	uint8_t carry = (ctx->cmd & 0x80) != 0;
	ctx->cmd <<= 1;

	//	BEQ.B	.get_next_byte
	if (ctx->cmd != 0)
	{
		printf("\t\t\t\t\tupdated current %x\n", ctx->cmd);
		printf("\t\t\t\t\tReturn Bit: %u\n", carry);
		return carry;
	}
		
	// 	MOVE.B	-(A5),D7
	--(ctx->src);
	// Update active cmd
	ctx->cmd = *ctx->src;
	printf("\t\t\t\t\tfetch new current %x\n", ctx->cmd);

	//	ADDX.B	D7,D7
	uint8_t newCarry = (ctx->cmd & 0x80) != 0;
	ctx->cmd <<= 1;
	ctx->cmd |= carry;	
	printf("\t\t\t\t\tReturn Bit: %u\n", newCarry);
	return newCarry;
}

uint32_t get_bits(Context* ctx, uint8_t countMinus1)
{
	uint32_t count = countMinus1 + 1U;
	printf("\t\t\t\tGetting %u bits\n", count);
	uint32_t acc = 0;
	for (uint8_t i = 0; i < count; ++i)
	{
		acc <<= 1;
		acc |= get_bit(ctx);
	}
	printf("\t\t\t\tReturn value is %u\n", acc);
	return acc;
}

static uint16_t	lz_table_1_bitcount_minus_1[] = { 0x3,  0x7,  0xb,     0xf };				// base add
static uint16_t	lz_table_1_add[] =              { 0x0, 0x10, 0x110, 0x1110 };	// number of bits (with 1 added)

// RETURN CODE IS "D0"
// res == "d1"
int32_t get_shortoffset(Context* ctx, uint16_t* res)
{
	printf("\t\t\tget_shortofffset\n");
	uint32_t acc = get_bits(ctx, 1);
	if (!acc)
	{
		*res = 0;
		return 0;
	}
	--acc;
	uint16_t bitcount = lz_table_1_bitcount_minus_1[acc];
	*res = lz_table_1_add[acc] + get_bits(ctx, bitcount);
	return -1;
}

void get_uint32_toffset(Context* ctx, uint32_t* res)
{
	printf("\t\t\tget_uint32_tofffset\n");
	uint32_t acc = get_bits(ctx, 1);
	// This one doesn't subtract 1..
	uint16_t bitcount = lz_table_1_bitcount_minus_1[acc];
	*res = lz_table_1_add[acc] + get_bits(ctx, bitcount);
}

void copy_string(Context* ctx, uint32_t offset, uint32_t count)
{
	printf("offset %u count %u\n", offset, count);
	const uint8_t* pCopyFrom = ctx->dst + offset + count;// code does +2 but it's already adjusted for dbf
	while (count--)
		fire_output(ctx, *--pCopyFrom);
}

void fire_literals(Context* ctx)
{
	// Check for literal copy
	uint8_t bit = get_bit(ctx);
	if (bit == 1)
	{
		// %1 -> Has literals
		bit = get_bit(ctx);

		// Calculate literal copy count
		// %0 -> single literal
		// %1 -> multiple literals
		uint32_t copycount = 0;		// assume single
		if (bit == 1)
		{
			// %1 multiple literals.
			static uint32_t bitcounts[]  = { 1, 1, 2, 9 };
			static uint32_t totals[]     = { 3, 3, 7, 0x3ff };
			static uint32_t copycounts[] = { 1, 4, 7, 0xe };
			for (uint32_t i = 0; i < 4; ++i)
			{
				uint32_t acc = get_bits(ctx, bitcounts[i]);
				//printf("Acc = %u\n", acc);
				if (acc != totals[i])
				{
					copycount = copycounts[i] + acc;
					break;
				}
			}
		}

		// Adjust for dbf
		++copycount;
		printf("\t\tCopying literals: %u\n", copycount);
		// literal copy
		while (copycount--)
			fire_output(ctx, *--(ctx->src));
	}
}

void fire_strings_00(Context* ctx)
{
	// %00
	// This is the "classical" LZ, where the length and offset are encoded separately.
	// There is a special case where the "last byte" is copied, although that could be
	// emulated by having an offset of 1

	// Get offset 0,1,2,3
	uint32_t offset1 = get_bits(ctx, 1);
	printf("\t\tCmd 0: first offset = %u\n", offset1);
	// offset1 is 0,1,2,3
	if (offset1 == 0)
	{
		// special case, repeat the same byte N times
		uint32_t copycount;
		get_uint32_toffset(ctx, &copycount);
		if (copycount == 0)
		{
			// Do nothing?
			assert(0);
			return;
		}
	
		uint8_t tocopy = *(ctx->dst);
		++copycount;
		printf("\t\tCopying same byte: %u\n", copycount);
		while (copycount--)
			fire_output(ctx, tocopy);
	}
	else
	{
		// Full LZ copy.
		// Fetch count, then offset.
		// The offset is always >= 5
static uint16_t more_table_1[] = { 3, 5, 7 };			// number of bits to fetch (-1)
static uint16_t more_table_2[] = { 5, 16+5, 64+16+5 };	// add base
		--offset1;
		uint32_t base = get_bits(ctx, more_table_1[offset1]);
		uint32_t length = base + more_table_2[offset1];
		printf("\t\tCmd 0: string length = %u\n", length);

		uint32_t offset;
		get_uint32_toffset(ctx, &offset);
		printf("\t\tCmd 0 string offset = %u\n", offset);
		copy_string(ctx, offset, length);
	}
}

void fire_strings_01(Context* ctx)
{
	// %01
	// Copy 2-byte string
	uint32_t offset = get_bits(ctx, 7);
	printf("\t\tCmd 1: copy two bytes @ offset %u\n", offset);
	copy_string(ctx, offset, 2);
}

void fire_strings_10(Context* ctx)
{
	// %10
	// Copy 3-byte string, or write a 0 byte.
	uint16_t offset;
	int32_t check = get_shortoffset(ctx, &offset);
	printf("\t\tCmd 2 offset = %u\n", offset);
	if (check == 0)
		// write 0 byte
		fire_output(ctx, 0 );
	else
	{
		// offset should probably be 21!
		printf("\t\tCmd 2: copy 3 bytes @ offset %u\n", offset);
		copy_string(ctx, offset, 3);
	}
}

void fire_strings_110(Context* ctx)
{
	// %11.0
	// Copy a value of 2^n.
	// This is pointless unless the shift is low e.g. 16
	printf("\t\t3.0\n");
	uint32_t shift = get_bits(ctx, 2);
	printf("\t\tshift %x\n", shift);
	fire_output(ctx, 1 << shift);
}

void fire_strings_1110(Context* ctx)
{
	// %11.1.0
	// Copy 4-byte string, or previous byte
	printf("\t\t3.1.0\n");
	uint16_t offset;
	int32_t check = get_shortoffset(ctx, &offset);
	printf("\t\t3.1.0 offset = %u\n", offset);
	if (check == 0)
		// Copy previous byte
		fire_output(ctx, *(ctx->dst));
	else
	{
		printf("\t\tCmd 3.1.0: copy 4 bytes @ offset %u\n", offset);
		copy_string(ctx, offset, 4);
	}
}

void fire_strings_1111(Context* ctx)
{
	// %11.1.1
	// Single 0xff byte, or 5-byte string
	printf("\t\t3.1.1\n");
	//.copy_single_shifted_bit_0 (!!)
	uint16_t offset;
	int32_t res = get_shortoffset(ctx, &offset);
	printf("\t\tres = %u\n", res);
	if (res == 0)
		// write 0xff byte
		fire_output(ctx, 0xff);
	else
		copy_string(ctx, offset, 5);
}

void fire_strings_11(Context* ctx)
{
	// %11
	// This has multiple variants depending on the successive bits
	// 110,
	// 1110, or
	// 1111
	if (get_bit(ctx) == 0)
		fire_strings_110(ctx);
	else
	{
		if (get_bit(ctx) == 0)
			fire_strings_1110(ctx);
		else
			fire_strings_1111(ctx);
	}
}

uint32_t fire_depack(const unsigned char *src, unsigned char *dstbase)
{
	uint32_t orig_size;

	// Check header
	if(!fire_header(src))
		return 0;
	orig_size = fire_origsize(src);

	uint32_t packedsize = fire_packedsize(src);
	src += packedsize;

	printf("Packed size: %u\n", packedsize);
	printf("Unpacked size: %u\n", orig_size);

	Context ctx;
	// Read starting command byte
	ctx.srcbase = src;
	ctx.dstbase = dstbase;
	ctx.dst = dstbase + orig_size;
	ctx.cmd = *--src;
	ctx.src = src;
	
	while (!fire_is_finished(&ctx))
	{
		// Literal regions always come first, if the next bit is 1
		fire_literals(&ctx);
		
		// We need to check here for completion, too
		if (fire_is_finished(&ctx))
			return orig_size;
			
		// Now do strings (LZ references)
		uint32_t stringsCmd = get_bits(&ctx, 1);
		if (stringsCmd == 0)
			fire_strings_00(&ctx);
		else if (stringsCmd == 1)
			fire_strings_01(&ctx);
		else if (stringsCmd == 2)
			fire_strings_10(&ctx);
		else if (stringsCmd == 3)
			fire_strings_11(&ctx);
	}
	return orig_size;
}

#define MAX_SIZE	(2*1024*1024)

int main(int argc, char** argv)
{
	if (argc < 3)
	{
		printf("unpack_fire <infile> <outfile>\n");
		return 1;
	}
	FILE* pInfile = fopen(argv[1], "rb");
	if (!pInfile)
	{
		printf("Can't read file\n");
		return 1;
	}

	uint8_t* pData = (uint8_t*) malloc(MAX_SIZE);
	int readBytes = fread(pData, 1, MAX_SIZE, pInfile);
	if (!readBytes)
	{
		printf("Can't read input file\n");
		free(pData);
		return 1;
	}
	fclose(pInfile);
	
	FILE* pOutfile = fopen(argv[2], "w");
	if (!pOutfile)
	{
		printf("Can't open output file\n");
		fclose(pOutfile);
		return 1;
	}
	
	uint8_t* pOutput = (uint8_t*) malloc(MAX_SIZE);
	int ret = fire_depack(pData, pOutput);
	free(pData);

	// Write the data
	int writeBytes = fwrite(pOutput, 1, ret, pOutfile);
	fclose(pOutfile);
	free(pOutput);

	if (!writeBytes)
	{
		printf("Failed to write output\n");	
		return 1;
	}
	return ret;
}

