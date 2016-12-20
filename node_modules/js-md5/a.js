var crypto = require('crypto');
var Buffer = require('buffer').Buffer;
var md5 = require('./src/md5.js');

// var message = '012345678901234567890123456789'
// var message2 = '一二三四五六七八九十一二三四五六七八九十一二三四五六七八九十'

// var message = new Uint8Array(new ArrayBuffer(20));

// console.log(crypto.createHash('md5').update(message, 'utf8').digest('binary'));
// console.log(md5.binary(message));
var message = '中文';

console.log(crypto.createHash('md5').update(message, 'utf8').digest('hex'));
console.log(crypto.createHash('md5').update(message, 'binary').digest('hex'));
console.log(crypto.createHash('md5').update(message, 'ascii').digest('hex'));


// var m = md5.update(message);
// m.binary();


// // console.log(crypto.createHash('md5').update(message, 'utf8').digest('binary'));
// console.log(htb(m));
// console.log(htb2(m));

// function htb(h) {
//   var h0 = h.h0, h1 = h.h1, h2 = h.h2, h3 = h.h3;
//   // return String.fromCharCode(h0 & 0xFF) + String.fromCharCode((h0 >> 8) & 0xFF) + 
//   //   String.fromCharCode((h0 >> 16) & 0xFF) + String.fromCharCode((h0 >> 24) & 0xFF) +
//   //   String.fromCharCode(h1 & 0xFF) + String.fromCharCode((h1 >> 8) & 0xFF) + 
//   //   String.fromCharCode((h1 >> 16) & 0xFF) + String.fromCharCode((h1 >> 24) & 0xFF) +
//   //   String.fromCharCode(h2 & 0xFF) + String.fromCharCode((h2 >> 8) & 0xFF) + 
//   //   String.fromCharCode((h2 >> 16) & 0xFF) + String.fromCharCode((h2 >> 24) & 0xFF) +
//   //   String.fromCharCode(h3 & 0xFF) + String.fromCharCode((h3 >> 8) & 0xFF) + 
//   //   String.fromCharCode((h3 >> 16) & 0xFF) + String.fromCharCode((h3 >> 24) & 0xFF);


//   return String.fromCharCode.apply(null, [
//       h0 & 0xFF, (h0 >> 8) & 0xFF, (h0 >> 16) & 0xFF, (h0 >> 24) & 0xFF,
//       h1 & 0xFF, (h1 >> 8) & 0xFF, (h1 >> 16) & 0xFF, (h1 >> 24) & 0xFF,
//       h2 & 0xFF, (h2 >> 8) & 0xFF, (h2 >> 16) & 0xFF, (h2 >> 24) & 0xFF,
//       h3 & 0xFF, (h3 >> 8) & 0xFF, (h3 >> 16) & 0xFF, (h3 >> 24) & 0xFF
//     ]);
// }

// function htb2(h) {
//   // var buffer = new ArrayBuffer(16);
//   //   var blocks = new Uint32Array(buffer);
//   //   var blocks2 = new Uint8Array(buffer);
//   //   blocks[0] = h.h0;
//   //   blocks[1] = h.h1;
//   //   blocks[2] = h.h2;
//   //   blocks[3] = h.h3;

//   // return String.fromCharCode.apply(null, blocks2);

//   var h0 = h.h0, h1 = h.h1, h2 = h.h2, h3 = h.h3;
//   return String.fromCharCode(
//     h0 & 0xFF, (h0 >> 8) & 0xFF, (h0 >> 16) & 0xFF, (h0 >> 24) & 0xFF, 
//     h1 & 0xFF, (h1 >> 8) & 0xFF, (h1 >> 16) & 0xFF, (h1 >> 24) & 0xFF, 
//     h2 & 0xFF, (h2 >> 8) & 0xFF, (h2 >> 16) & 0xFF, (h2 >> 24) & 0xFF, 
//     h3 & 0xFF, (h3 >> 8) & 0xFF, (h3 >> 16) & 0xFF, (h3 >> 24) & 0xFF
//   );
// }

// console.time('s');
// for (var i = 0;i < 100000;++i) {
//   htb(m);
// }
// console.timeEnd('s');

// console.time('s');
// for (var i = 0;i < 100000;++i) {
//   htb2(m);
// }
// console.timeEnd('s');
