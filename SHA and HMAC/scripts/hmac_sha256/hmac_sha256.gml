/// @jujuadams 2021-09-16
///
/// @param keyString
/// @param message

function hmac_sha256(_key, _message)
{
    var _block_size  = 64; //bytes
    var _return_size = 32; //bytes
    
    var _inner_pad_buffer = buffer_create(_block_size + string_byte_length(_message), buffer_fixed, 1);
    var _outer_pad_buffer = buffer_create(_block_size + _return_size, buffer_fixed, 1);
    
    var _key_length = string_byte_length(_key);
    if (_key_length > _block_size)
    {
        //If the key is longer than the block size, we hash the key and use that instead
        var _hash = string_sha256(_key, false);
        
        //Add the (hashed) key to the inner and outer pad buffers, XOR'd as necessary
        var _n = 0;
        repeat(8)
        {
            var _value = _hash[_n];
            //Reverse endianness
            _value = ((_value & 0x000000ff) << 24)
                   | ((_value & 0x0000ff00) <<  8)
                   | ((_value & 0x00ff0000) >>  8)
                   | ((_value & 0xff000000) >> 24);
            
            buffer_write(_inner_pad_buffer, buffer_u32, 0x36363636 ^ _value);
            buffer_write(_outer_pad_buffer, buffer_u32, 0x5c5c5c5c ^ _value);
            
            _n++;
        }
        
        //Set the key length to the return size for the benefit of figuring out how much padding to add
        _key_length = _return_size;
    }
    else
    {
        //If the key is smaller than the block size, just use the key
        var _n = 1;
        repeat(_key_length)
        {
            var _value = string_byte_at(_key, _n);
            buffer_write(_inner_pad_buffer, buffer_u8, 0x36 ^ _value);
            buffer_write(_outer_pad_buffer, buffer_u8, 0x5c ^ _value);
            _n++;
        }
    }
    
    //Pad out the rest too!
    buffer_fill(_inner_pad_buffer, _key_length, buffer_u8, 0x36, _block_size - _key_length);
    buffer_fill(_outer_pad_buffer, _key_length, buffer_u8, 0x5c, _block_size - _key_length);
    buffer_seek(_inner_pad_buffer, buffer_seek_start, _block_size);
    buffer_seek(_outer_pad_buffer, buffer_seek_start, _block_size);
    
    //Append the message to the inner padding, and hash the whole lot
    buffer_write(_inner_pad_buffer, buffer_text, _message);
    var _hash = buffer_sha256(_inner_pad_buffer, 0, buffer_tell(_inner_pad_buffer), true, false);
    
    //Add the (hashed) inner pad to the outer pad buffer
    var _n = 0;
    repeat(8)
    {
        var _value = _hash[_n];
        
        //Reverse endianness
        buffer_write(_outer_pad_buffer, buffer_u32, ((_value & 0x000000ff) << 24)
                                                  | ((_value & 0x0000ff00) <<  8)
                                                  | ((_value & 0x00ff0000) >>  8)
                                                  | ((_value & 0xff000000) >> 24));
        
        _n++;
    }
    
    //And finally hash the outer padding too
    return buffer_sha256(_outer_pad_buffer, 0, buffer_tell(_outer_pad_buffer), true);
}