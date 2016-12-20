var fs = require('fs');
var TextDecoder = require('text-encoding').TextDecoder;
var KaitaiStream = require("./KaitaiStream.js")
var Pefile = require("./pefile.js");

var ssdeep = require("ssdeep.js");
var md5 = require('js-md5');
var sha256 = require('js-sha256');
var CircularJSON = require('circular-json');

var data;
if(process.argv.length > 2){
  data = fs.readFileSync(process.argv[2]);
  ReadPEFile(data);
} else {
  console.log("Usage: node test.js [FILE]")
  process.exit(1);
}

function ReadPEFile(data){
  var pefile = new Pefile(data);
  //console.dir(CircularJSON.stringify(pefile));
  console.log(pefile.dump_info())
  //console.log("Imphash:", pefile.get_imphash())
}
