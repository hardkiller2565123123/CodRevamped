#include <cstddef>

// LibTomCrypt entropy hooks are intentionally unavailable in the embedded/offline client.
// Keep exactly one definition project-wide so imported game modules do not collide at link time.
extern "C"
{
	int s_read_arc4random(void*, size_t) { return -1; }
	int s_read_getrandom(void*, size_t) { return -1; }
	int s_read_urandom(void*, size_t) { return -1; }
	int s_read_ltm_rng(void*, size_t) { return -1; }
}
