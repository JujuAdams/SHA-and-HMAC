/// @jujuadams 2021-09-16
/// 
/// @param buffer
/// @param [offset]
/// @param [size]
/// @param [disposeBuffer=false]
/// @param [returnString=true]

#macro __SHA512_BLOCK_SIZE            128  ///bytes
#macro __SHA512_WORD_DATATYPE  buffer_u64
#macro __SHA512_WORD_SIZE               8  ///bytes
#macro __SHA512_BLOCK_WORDS    (__SHA512_BLOCK_SIZE / __SHA512_WORD_SIZE)
#macro __SHA512_ROUND_COUNT            80

//Reused arrays
global.__sha512_round_constants = [ 0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538, 
                                    0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe, 
                                    0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 
                                    0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 
                                    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab, 
                                    0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725, 
                                    0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 
                                    0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b, 
                                    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218, 
                                    0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 
                                    0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 
                                    0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec, 
                                    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c, 
                                    0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6, 
                                    0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 
                                    0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817];

global.__sha512_message_schedule = array_create(__SHA512_ROUND_COUNT, 0x00);

function buffer_sha512(_in_buffer, _in_offset = 0, _size = (buffer_get_size(_in_buffer) - _in_offset), _dispose = false, _return_string = true)
{
    if (!buffer_exists(_in_buffer)) show_error("Buffer " + string(_in_buffer) + " doesn't exist", true);
    if (_in_offset + _size > buffer_get_size(_in_buffer)) show_error("Attempting to read outside buffer (offset + size = " + string(_in_offset + _size) + ", buffer size = " + string(buffer_get_size(_in_buffer)) + ")", true);
    
    var _state_array_0 = 0x6a09e667f3bcc908;
    var _state_array_1 = 0xbb67ae8584caa73b;
    var _state_array_2 = 0x3c6ef372fe94f82b;
    var _state_array_3 = 0xa54ff53a5f1d36f1;
    var _state_array_4 = 0x510e527fade682d1;
    var _state_array_5 = 0x9b05688c2b3e6c1f;
    var _state_array_6 = 0x1f83d9abfb41bd6b;
    var _state_array_7 = 0x5be0cd19137e2179;
    
    var _block_count = ceil(_size / __SHA512_BLOCK_SIZE);
    
    //If we don't have space after the final block to store the bit size of the input buffer, add on an extra block
    var _last_block_remaining = __SHA512_BLOCK_SIZE*_block_count - _size;
    if (_last_block_remaining < 17) _block_count++; //Ensure we have enough room to append a 0x80 byte and a 128-bit integer at the end
    
    if (_dispose)
    {
        var _buffer = _in_buffer;
        var _offset = _in_offset;
        
        buffer_resize(_buffer, _offset + __SHA512_BLOCK_SIZE*_block_count);
    }
    else
    {
        var _buffer = buffer_create(__SHA512_BLOCK_SIZE*_block_count, buffer_fixed, 1);
        var _offset = 0;
        
        buffer_copy(_in_buffer, _offset, _size, _buffer, 0);
    }
    
    buffer_poke(_buffer, _offset + _size, buffer_u8, 0x80);
    
    //Store the number of bits right at the end of the buffer
    //This is stored as a big endian number
    //For SHA512 the number we append should be a 128-bit integer but we don't have that datatype, nor would we expect to ever process that much data!
    var _bits = 8*_size;
    buffer_seek(_buffer, buffer_seek_start, _offset + __SHA512_BLOCK_SIZE*_block_count - 8);
    buffer_write(_buffer, buffer_u8, _bits >> 56);
    buffer_write(_buffer, buffer_u8, _bits >> 48);
    buffer_write(_buffer, buffer_u8, _bits >> 40);
    buffer_write(_buffer, buffer_u8, _bits >> 32);
    buffer_write(_buffer, buffer_u8, _bits >> 24);
    buffer_write(_buffer, buffer_u8, _bits >> 16);
    buffer_write(_buffer, buffer_u8, _bits >>  8);
    buffer_write(_buffer, buffer_u8, _bits      );
    
    //Jump back to where the data begins
    buffer_seek(_buffer, buffer_seek_start, _offset);
    
    //Perform round for each block
    repeat(_block_count)
    {
        var _message_schedule = global.__sha512_message_schedule;
        
        var _i = 0;
        repeat(__SHA512_BLOCK_WORDS)
        {
            var _value = buffer_read(_buffer, __SHA512_WORD_DATATYPE);
            //Reverse endianness
            _message_schedule[@ _i] = ((_value & 0x00000000000000ff) << 56)
                                    | ((_value & 0x000000000000ff00) << 40)
                                    | ((_value & 0x0000000000ff0000) << 24)
                                    | ((_value & 0x00000000ff000000) <<  8)
                                    | ((_value & 0x000000ff00000000) >>  8)
                                    | ((_value & 0x0000ff0000000000) >> 24)
                                    | ((_value & 0x00ff000000000000) >> 40)
                                    | __sha512_rshift_uint64((_value & 0xff00000000000000), 56);
            
            ++_i;
        }
        
        var _i = __SHA512_BLOCK_WORDS;
        repeat(__SHA512_ROUND_COUNT - __SHA512_BLOCK_WORDS)
        {
            var _p = _message_schedule[_i - 15];
            var _q = _message_schedule[_i -  2];
            
            var _value = (__sha512_rshift_uint64(_q, 19) | (_q << 45)) ^ (__sha512_rshift_uint64(_q, 61) | (_q << 3)) ^ __sha512_rshift_uint64(_q, 6); //sigma 1
                _value = __sha512_add_uint64(_value, _message_schedule[_i - 7]);
                _value = __sha512_add_uint64(_value, (__sha512_rshift_uint64(_p, 1) | (_p << 63)) ^ (__sha512_rshift_uint64(_p, 8) | (_p << 56)) ^ __sha512_rshift_uint64(_p, 7)); //sigma 0
                _value = __sha512_add_uint64(_value, _message_schedule[_i - 16]);
            
            _message_schedule[@ _i] = _value;
            
            _i++;
        }
        
        var a = _state_array_0;
        var b = _state_array_1;
        var c = _state_array_2;
        var d = _state_array_3;
        var e = _state_array_4;
        var f = _state_array_5;
        var g = _state_array_6;
        var h = _state_array_7;
        
        var _i = 0;
        repeat(__SHA512_ROUND_COUNT)
        {
            var t1 = h;
                t1 = __sha512_add_uint64(t1, (__sha512_rshift_uint64(e, 14) | (e << 50))   ^   (__sha512_rshift_uint64(e, 18) | (e << 46))   ^   (__sha512_rshift_uint64(e, 41) | (e << 23))); //sum 1
                t1 = __sha512_add_uint64(t1, (e & f) ^ (~e & g));
                t1 = __sha512_add_uint64(t1, global.__sha512_round_constants[_i]);
                t1 = __sha512_add_uint64(t1, _message_schedule[_i]);
               
            var t2 = (__sha512_rshift_uint64(a, 28) | (a << 36))   ^   (__sha512_rshift_uint64(a, 34) | (a << 30))   ^   (__sha512_rshift_uint64(a, 39) | (a << 25)); //sum 0
                t2 = __sha512_add_uint64(t2, ((a & b) ^ (a & c) ^ (b & c)));
        
            h = g;
            g = f;
            f = e;
            e = __sha512_add_uint64(d, t1);
            d = c;
            c = b;
            b = a;
            a = __sha512_add_uint64(t1, t2);
        
            ++_i;
        }
    
        _state_array_0 = __sha512_add_uint64(_state_array_0, a);
        _state_array_1 = __sha512_add_uint64(_state_array_1, b);
        _state_array_2 = __sha512_add_uint64(_state_array_2, c);
        _state_array_3 = __sha512_add_uint64(_state_array_3, d);
        _state_array_4 = __sha512_add_uint64(_state_array_4, e);
        _state_array_5 = __sha512_add_uint64(_state_array_5, f);
        _state_array_6 = __sha512_add_uint64(_state_array_6, g);
        _state_array_7 = __sha512_add_uint64(_state_array_7, h);
    }
    
    if (_return_string)
    {
        //Construct hex string from array
        //We use a buffer method here to avoid string concat
        //We also reuse the working buffer for the sake of reducing the memory footprint slightly
        buffer_seek(_buffer, buffer_seek_start, 0);
        
        var _i = 0;
        repeat(8)
        {
            switch(_i)
            {
                case 0: var _value = _state_array_0; break;
                case 1: var _value = _state_array_1; break;
                case 2: var _value = _state_array_2; break;
                case 3: var _value = _state_array_3; break;
                case 4: var _value = _state_array_4; break;
                case 5: var _value = _state_array_5; break;
                case 6: var _value = _state_array_6; break;
                case 7: var _value = _state_array_7; break;
            }
            
            var _j = 8*__SHA512_WORD_SIZE;
            repeat(__SHA512_WORD_SIZE)
            {
                var _msf = (_value >> (_j-4)) & 0x0f;
                var _lsf = (_value >> (_j-8)) & 0x0f;
                buffer_write(_buffer, buffer_u8, (_msf < 10)? (_msf + 48) : (_msf + 87));
                buffer_write(_buffer, buffer_u8, (_lsf < 10)? (_lsf + 48) : (_lsf + 87));
                
                _j -= 8;
            }
            
            ++_i;
        }
        
        buffer_write(_buffer, buffer_u8, 0x00);
        buffer_seek(_buffer, buffer_seek_start, 0);
        var _string = buffer_read(_buffer, buffer_string);
        
        //Get rid of the working buffer
        buffer_delete(_buffer);
        
        return _string;
    }
    else
    {
        return [ _state_array_0,
                 _state_array_1,
                 _state_array_2,
                 _state_array_3,
                 _state_array_4,
                 _state_array_5,
                 _state_array_6,
                 _state_array_7 ];
    }
}

function __sha512_add_uint64(_a, _b)
{
    //GameMaker stores its 64-bit integers as *signed* integers
    //The SHA512 algorithm requires addition to be done with unsigned integers
    //This means we need to trick GameMaker into doing unsigned addition for us
    
    var _lower = (_a & 0xffffffff) + (_b & 0xffffffff);
    return (((_a >> 32) + (_b >> 32) + (_lower >> 32)) << 32) | (_lower & 0xffffffff);
}

function __sha512_rshift_uint64(_x, _s)
{
    //Emulates the >>> operator
    return (_x >> _s) & ((1 << (64 - _s)) - 1);
}