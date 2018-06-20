---
layout: post
title: "practical bughunting pt.0x1"
---
# practical bughunting pt 1 (null ptr ftw) 

This will begin a series of blog posts documenting my independant learning contract in security bug hunting! My goal was to write an exploit for an existing well documented bug and then to find a bug in some media parser manually. For the well documented bug to investigate i chose a null pointer dereference bug in ffmpeg which is documented in [a bug hunter's diary](http://www.trapkit.de/books/bhd/en.html) chapter 4.

## retrieving the vulnerable code

The svn command cited on the book's website (`svn checkout svn://svn.ffmpeg.org/ffmpeg/trunk@16556 ffmpeg`) did not work for me, the error message returned to me was as follows:

```
 A    ffmpeg/MAINTAINERS
 A    ffmpeg/cmdutils.h
  U   ffmpeg
 svn: warning: W205011: Error handling externals definition for 'ffmpeg/libswscale':
 svn: warning: W170000: URL 'svn://svn.ffmpeg.org/mplayer/trunk/libswscale' at revision 38109 doesn't exist
 Checked out revision 16556.
 svn: E205011: Failure occurred processing one or more externals definitions
```

Although the error message implies missing files on the remote repository my final solution did not involve resolving anything like that. Since the ffmpeg project has moved to github since the book's writing i decided to use git and find how to use svn revision numbers with git. I found this [handy tutorial](https:// www.ffmpeg.org/git-howto.html#Finding-a-specific-svn-revision) and then the following series of commands gave me the complete vulnerable source code:

```
 git clone git://source.ffmpeg.org/ffmpeg
 git checkout -b svn_16556 :/'as revision 16556'
```

## describing the vulnerability

As it relates to the null pointer dereference bug we will be targeting the 4xm file format parser within ffmpeg. 4xm files have the following general structure:

```
 RIFF header
   LIST-HEAD chunk
     LIST-HNFO chunk
   LIST-TRK_ chunk
     LIST-VTRK chunk       [video track]
     LIST-STRK chunk       [sound track]
     [..more tracks..]
   LIST-MOVI chunk
     LIST-FRAM chunk
     LIST-FRAM chunk
     LIST-FRAM chunk
     [..more frame tracks..]
```

The relevant section of code is in `libavformat/4xm.c` on line 93:

```c
static int fourxm_read_header(AVFormatContext *s,
                              AVFormatParameters *ap)
{
    ByteIOContext *pb = s->pb;
    unsigned int fourcc_tag;
    unsigned int size;
    int header_size;
    FourxmDemuxContext *fourxm = s->priv_data;
    unsigned char *header;
    int i;
    int current_track = -1;
    AVStream *st;

    fourxm->track_count = 0;
    fourxm->tracks = NULL;
    fourxm->selected_track = 0;
    fourxm->fps = 1.0;

    /* skip the first 3 32-bit numbers */
    url_fseek(pb, 12, SEEK_CUR);

    /* check for LIST-HEAD */
    GET_LIST_HEADER();
    header_size = size - 4;
    if (fourcc_tag != HEAD_TAG)
        return AVERROR_INVALIDDATA;

    /* allocate space for the header and load the whole thing */
    header = av_malloc(header_size);
    if (!header)
        return AVERROR(ENOMEM);
    if (get_buffer(pb, header, header_size) != header_size)
        return AVERROR(EIO);

     /* take the lazy approach and search for any and all vtrk and strk         chunks */
     for (i = 0; i < header_size - 8; i++) {
         fourcc_tag = AV_RL32(&header[i]);
         size = AV_RL32(&header[i + 4]);

         if (fourcc_tag == std__TAG) {
             fourxm->fps = av_int2flt(AV_RL32(&header[i + 12]));
         } else if (fourcc_tag == vtrk_TAG) {
             /* check that there is enough data */
             if (size != vtrk_SIZE) {
                 av_free(header);
                 return AVERROR_INVALIDDATA;
             }
             fourxm->width = AV_RL32(&header[i + 36]);
             fourxm->height = AV_RL32(&header[i + 40]);

             /* allocate a new AVStream */
             st = av_new_stream(s, 0);
             if (!st)
                 return AVERROR(ENOMEM);
             av_set_pts_info(st, 60, 1, fourxm->fps);

             fourxm->video_stream_index = st->index;

             st->codec->codec_type = CODEC_TYPE_VIDEO;
             st->codec->codec_id = CODEC_ID_4XM;
             st->codec->extradata_size = 4;
             st->codec->extradata = av_malloc(4);
             AV_WL32(st->codec->extradata, AV_RL32(&header[i + 16]));
             st->codec->width = fourxm->width;
             st->codec->height = fourxm->height;

             i += 8 + size;
         } else if (fourcc_tag == strk_TAG) {
             /* check that there is enough data */
             if (size != strk_SIZE) {
                 av_free(header);
                 return AVERROR_INVALIDDATA;
             }
             current_track = AV_RL32(&header[i + 8]); // !! uint -> int
             if (current_track + 1 > fourxm->track_count) { // b00m
                 fourxm->track_count = current_track + 1;
                 if((unsigned)fourxm->track_count >= UINT_MAX /                 sizeof(AudioTrack))
                     return -1;
                 fourxm->tracks = av_realloc(fourxm->tracks, // we can avoid this s.t fourxm->tracks is null
                     fourxm->track_count * sizeof(AudioTrack));
                 if (!fourxm->tracks) {
                     av_free(header);
                     return AVERROR(ENOMEM);
                 }
             }
             fourxm->tracks[current_track].adpcm = AV_RL32(&header[i + 12]);       // here we deref whatever addr we can put into current_track
             fourxm->tracks[current_track].channels = AV_RL32(&header[i + 36]);
             fourxm->tracks[current_track].sample_rate = AV_RL32(&header[i +    40]);
             fourxm->tracks[current_track].bits = AV_RL32(&header[i + 44]);
             i += 8 + size;

             /* allocate a new AVStream */
             st = av_new_stream(s, current_track);
             if (!st)
                 return AVERROR(ENOMEM);

             av_set_pts_info(st, 60, 1, fourxm->tracks[current_track].          sample_rate);

             fourxm->tracks[current_track].stream_index = st->index;

             st->codec->codec_type = CODEC_TYPE_AUDIO;
             st->codec->codec_tag = 0;
             st->codec->channels = fourxm->tracks[current_track].channels;
             st->codec->sample_rate = fourxm->tracks[current_track].            sample_rate;
             st->codec->bits_per_coded_sample = fourxm->tracks[current_track].  bits;
             st->codec->bit_rate = st->codec->channels * st->codec-             >sample_rate *
                 st->codec->bits_per_coded_sample;
             st->codec->block_align = st->codec->channels * st->codec-          >bits_per_coded_sample;
             if (fourxm->tracks[current_track].adpcm)
                 st->codec->codec_id = CODEC_ID_ADPCM_4XM;
             else if (st->codec->bits_per_coded_sample == 8)
                 st->codec->codec_id = CODEC_ID_PCM_U8;
             else
                 st->codec->codec_id = CODEC_ID_PCM_S16LE;
         }
     }

     av_free(header);

     /* skip over the LIST-MOVI chunk (which is where the stream should be */
     GET_LIST_HEADER();
     if (fourcc_tag != MOVI_TAG)
         return AVERROR_INVALIDDATA;

     /* initialize context members */
     fourxm->video_pts = -1;  /* first frame will push to 0 */
     fourxm->audio_pts = 0;

     return 0;
 }
```

Breaking this down; the author tells us that the vulnerability lies in the fact that we can avoid the line `c fourxm->tracks = av_realloc(fourxm->tracks,...` and thus when we arrive at `c fourxm->tracks[current_track].adpcm = AV_RL32(&header[i + 12]);` the `c fourxm->tracks` will be null and we can control the address to write to with the `c current_track` variable which we control. Breaking this down even further the fourxm struct has the following members which include the relevant member `c AudioTrack *tracks;`:

```c
 typedef struct FourxmDemuxContext {
     int width;
     int height;
     int video_stream_index;
     int track_count;
     AudioTrack *tracks;
     int selected_track;

     int64_t audio_pts;
     int64_t video_pts;
     float fps;
 } FourxmDemuxContext;
```

The `c AudioTrack` struct has the following members (and all the members are 4 bytes in size):

```c
 typedef struct AudioTrack {
     int sample_rate;        
     int bits;               
     int channels;           
     int stream_index;       
     int adpcm;              
 } AudioTrack;
```

again looking at the line of interest `c fourxm->tracks[current_track].adpcm = AV_RL32(&header[i + 12]);` i was interested in this `c AV_RL32` macro. I found its definition in libavutil/intreadwrite.h on line 80:

```c
#  define AV_RL32(x)    bswap_32(AV_RN32(x))
```

as we continue down the line of function definitions we can see in libavutil/bswap.h the definition for the `bswap_32` function:

```c
static av_always_inline av_const uint32_t bswap_32(uint32_t x)
 {
     x= ((x<<8)&0xFF00FF00) | ((x>>8)&0x00FF00FF);
     x= (x>>16) | (x<<16);
     return x;
 }
```

this one is a bit hard to follow but basically its doing some bytes swapping, you can simulate what it does in the python interpreter like so:

```python
>>> x = 0xaabbccdd

>>> x = ((x<<8)&0xFF00FF00) | ((x>>8)&0x00FF00FF)

>>> hex(x)
'0xbbaaddcc'

>>> x= ((x>>16) | (x<<16)) & 0xffffffff

>>> # the extra & at the end just simulates the truncation

>>> # C would do since python has infinite precision

>>> hex(x)
'0xddccbbaa'
```

Reviewing once again what tobias says in the book:

```
 1. fourxm->tracks is initialized with NULL (see line 107).
 2. If the processed media file contains a strk chunk, the value of
 current_track is extracted from the user-controlled data of the
 chunk (see line 166).
 3. If the value of current_track + 1 is less than zero, the heap buffer
 isn’t allocated.
 4. fourxm->tracks still points to memory address NULL.
 5. The resulting NULL pointer is then dereferenced by the usercontrolled
 value of current_track, and four 32-bit values of usercontrolled
 data are assigned to the dereferenced locations (see
 lines 178–181).
 6. Four user-controlled memory locations can be overwritten with
 four user-controlled data bytes each.
```

## verifying the vulnerability at a low level

You might be thinking to yourself - this arbitrary write is simple! fourxm->tracks is null, plus our controlled current_track gives us an arbitrary write! Afterwards you may be surprised to find the following assembly for that assignment:

Ok so in the book tobias says the algorithm is as such:

```
 edx + ((ebx + ebx * 4) << 2) + 0x10 = destination address of write operation
```

Ours might look a bit different due to 64bit binary... let's dissect the asm:

```
 |||   0x0046171e      4863ca         movsxd rcx, edx
 |||   0x00461721      418b742e0c     mov esi, dword [r14 + rbp + 0xc] ; [0xc:4]=-1 ; 12
 |||   0x00461726      488b7c2408     mov rdi, qword [rsp + 8]    ; [0x8:8]=-1 ; 8
 |||   0x0046172b      488d0c89       lea rcx, [rcx + rcx*4]
 |||   0x0046172f      83c330         add ebx, 0x30               ; '0'
 |||   0x00461732      4c8d2c8d0000.  lea r13, [rcx*4]
 |||   0x0046173a      48894c2410     mov qword [rsp + 0x10], rcx
 |||   0x0046173f      4c01e8         add rax, r13                ; 'o'
 |||   0x00461742      897010         mov dword [rax + 0x10], esi
```

As we begin edx is our current track. `movsxd` extends our 32 bit value to a 64 bit value so 0xffffffff becomes 0xffffffffffffffff

At 0x0046172b we see `rcx = rcx + rcx * 4`, then at 0x00461732 `r13 = rcx * 4` once again.

Thus we have `r13 = (rcx + rcx * 4) * 4` or the equivalent: `r13 = (rcx + rcx * 4) << 2` as tobias wrote.

