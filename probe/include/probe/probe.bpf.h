/*
 * DDSketch implementation:
 */

#define DDSKETCH_M 750

struct ddskectch_bucket {
    __u32 bucket[DDSKETCH_M];
    __u32 total_cnt;
} __attribute__((packed));