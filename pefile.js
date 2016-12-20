var KaitaiStream = require("./KaitaiStream.js")

var TextDecoder = require('text-encoding').TextDecoder;
var ssdeep = require("ssdeep.js");
var md5 = require('js-md5');
var sha256 = require('js-sha256');

var exts = ['ocx', 'sys', 'dll'];
var oleauth32_ord_names = {}
var ws2_32_ord_names = {}

var Pefile = (function() {

  function Pefile(_io, _parent, _root) {
    var ke = new KaitaiStream(_io);
    this._io = ke;
    this._parent = _parent;
    this._root = _root || this;

    this.PECONSOLE = "";
    this.IMPORT_STRING = "";
    this.IMPHASH = "";
    this.IMPDEEP = "";
    this.IMPORT_SECTION_VIRTUAL_ADDRESS;
    this.IMPORT_SECTION_POINTER_TO_RAW;


    this.CURRENT_OFFSET = 0;
    this.GenerateOutput = function(pos, offset, name, value){

      var hex_offset = this.CURRENT_OFFSET.toString(16).toUpperCase();
      this.CURRENT_OFFSET = this.CURRENT_OFFSET + offset;
      var spaces1 = 4 - hex_offset.length;
      var spacer1 = "   ";

      var hex_pos = (pos-offset).toString(16).toUpperCase()
      var spacer2 = "         ";
      var spaces2 = 9 - hex_pos.length;

      var name_spacer = ":                              ";
      if(typeof value != 'number' && typeof value != 'string' ){
        var newval = ""
        value = value.reverse()
        for(i=0; i< value.length; i++){
          newval += value[i].toString(16).toUpperCase();
        }
        value = "0x" + parseInt(newval, 16).toString(16).toUpperCase();
        if(parseInt(value) == 0) value = "";
      } else {
        if(typeof value != 'string' ) value = "0x" + value.toString(16).toUpperCase();
      }
      GenerateConsoleOutput('0x' + hex_pos + spacer2.substring(0,spaces2) +"0x"+hex_offset+spacer1.substring(0,spaces1)+ name + name_spacer.substring(0,(name_spacer.length - name.length) ) +value, this);
    }

    this.GenerateHeader = function(text){
      this.CURRENT_OFFSET = 0;
      GenerateConsoleOutput(text, this);
    }

    this.IMAGE_DOS_HEADER = new IMAGE_DOS_HEADER(this._io, this, this._root);
    this.mz2 = this._io.readBytes((this.IMAGE_DOS_HEADER.e_lfanew - 64));
    this.IMAGE_NT_HEADERS = this._io.ensureFixedContents([80, 69, 0, 0]);
    this.GenerateHeader("");
    this.GenerateHeader("----------NT_HEADERS----------");
    this.GenerateHeader("");
    this.GenerateHeader("[IMAGE_NT_HEADERS]");
    this.GenerateOutput(this._io.pos, 2, "Signature", this.IMAGE_NT_HEADERS);

    this.IMAGE_FILE_HEADER = new IMAGE_FILE_HEADER(this._io, this, this._root);
    this._raw_optionalHeader = this._io.readBytes(this.IMAGE_FILE_HEADER.SizeOfOptionalHeader);
    var _io__raw_optionalHeader = new KaitaiStream(this._raw_optionalHeader);
    this.optionalHeader = new OptionalHeader(_io__raw_optionalHeader, this, this._root);
    this.sections = new Array(this.IMAGE_FILE_HEADER.NumberOfSections);
    this.GenerateHeader("");
    this.GenerateHeader("----------PE Sections----------");
    this.GenerateHeader("");
    for (var i = 0; i < this.IMAGE_FILE_HEADER.NumberOfSections; i++) {
      this.sections[i] = new Section(this._io, this, this._root);
      var body = this.sections[i].body;
      this.sections[i]["MD5"] = md5(body);
      this.sections[i]["SHA256"] = sha256(body);
      this.sections[i]["ssdeep"] = ssdeep.digest(body);
      this.GenerateHeader("MD5     hash: " + this.sections[i]["MD5"]);
      this.GenerateHeader("SHA-256 hash: " + this.sections[i]["SHA256"]);
      this.GenerateHeader("ssdeep  hash: " + this.sections[i]["ssdeep"]);
      this.GenerateHeader("");
      this.CURRENT_OFFSET = 0;
    }


    this.IMAGE_IMPORT_DESCRIPTOR_ARRAY = FindImports(this);

    this.dump_info = function(){
      return this.PECONSOLE;
    }

    this.get_imphash = function(){
      return this.IMPHASH;
    }

    this.get_impdeep = function(){
      return this.IMPDEEP;
    }




  }

  var IMAGE_OPTIONAL_HEADER = (function() {
    IMAGE_OPTIONAL_HEADER.PeFormat = Object.freeze({
      'IMAGE_FILE_RELOCS_STRIPPED':          0x0001,
      'IMAGE_FILE_EXECUTABLE_IMAGE':         0x0002,
      'IMAGE_FILE_LINE_NUMS_STRIPPED':       0x0004,
      'IMAGE_FILE_LOCAL_SYMS_STRIPPED':      0x0008,
      'IMAGE_FILE_AGGRESIVE_WS_TRIM':        0x0010,
      'IMAGE_FILE_LARGE_ADDRESS_AWARE':      0x0020,
      'IMAGE_FILE_16BIT_MACHINE':            0x0040,
      'IMAGE_FILE_BYTES_REVERSED_LO':        0x0080,
      'IMAGE_FILE_32BIT_MACHINE':            0x0100,
      'IMAGE_FILE_DEBUG_STRIPPED':           0x0200,
      'IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP':  0x0400,
      'IMAGE_FILE_NET_RUN_FROM_SWAP':        0x0800,
      'IMAGE_FILE_SYSTEM':                   0x1000,
      'IMAGE_FILE_DLL':                      0x2000,
      'IMAGE_FILE_UP_SYSTEM_ONLY':           0x4000,
      'IMAGE_FILE_BYTES_REVERSED_HI':        0x8000
    });

    IMAGE_OPTIONAL_HEADER.Subsystem = Object.freeze({
      'IMAGE_SUBSYSTEM_UNKNOWN':                   0,
      'IMAGE_SUBSYSTEM_NATIVE':                    1,
      'IMAGE_SUBSYSTEM_WINDOWS_GUI':               2,
      'IMAGE_SUBSYSTEM_WINDOWS_CUI':               3,
      'IMAGE_SUBSYSTEM_OS2_CUI':                   5,
      'IMAGE_SUBSYSTEM_POSIX_CUI':                 7,
      'IMAGE_SUBSYSTEM_NATIVE_WINDOWS':            8,
      'IMAGE_SUBSYSTEM_WINDOWS_CE_GUI':            9,
      'IMAGE_SUBSYSTEM_EFI_APPLICATION':          10,
      'IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER':  11,
      'IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER':       12,
      'IMAGE_SUBSYSTEM_EFI_ROM':                  13,
      'IMAGE_SUBSYSTEM_XBOX':                     14,
      'IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION': 16
    });

    function IMAGE_OPTIONAL_HEADER(_io, _parent, _root) {
      this._io = _io;
      this._parent = _parent;
      this._root = _root || this;
      _root.GenerateHeader("");
      _root.GenerateHeader("----------OPTIONAL_HEADER----------");
      _root.GenerateHeader("");
      _root.GenerateHeader("[IMAGE_OPTIONAL_HEADER]");
      this.Magic = this._io.readU2le();
      _root.GenerateOutput(this._io.pos, 2, "Magic", this.Magic);
      this.MajorLinkerVersion = this._io.readU1();
      _root.GenerateOutput(this._io.pos, 1, "MajorLinkerVersion", this.MajorLinkerVersion);
      this.MinorLinkerVersion = this._io.readU1();
      _root.GenerateOutput(this._io.pos, 1, "MinorLinkerVersion", this.MinorLinkerVersion);
      this.SizeOfCode = this._io.readU4le();
      _root.GenerateOutput(this._io.pos, 4, "SizeOfCode", this.SizeOfCode);
      this.SizeOfInitializedData = this._io.readU4le();
      _root.GenerateOutput(this._io.pos, 4, "SizeOfInitializedData", this.SizeOfInitializedData);
      this.SizeOfUninitializedData = this._io.readU4le();
      _root.GenerateOutput(this._io.pos, 4, "SizeOfUninitializedData", this.SizeOfUninitializedData);
      this.AddressOfEntryPoint = this._io.readU4le();
      _root.GenerateOutput(this._io.pos, 4, "AddressOfEntryPoint", this.AddressOfEntryPoint);
      this.BaseOfCode = this._io.readU4le();
      _root.GenerateOutput(this._io.pos, 4, "BaseOfCode", this.BaseOfCode);
      if (this.Magic == 267) {
        this.BaseOfData = this._io.readU4le();
        _root.GenerateOutput(this._io.pos, 4, "BaseOfData", this.BaseOfData);
      }

      if (this.Magic == 267) {
        this.ImageBase = this._io.readU4le();
        _root.GenerateOutput(this._io.pos, 4, "ImageBase", this.ImageBase);
      }
      if (this.Magic == 523) {
        this.ImageBase = this._io.readU8le();
        _root.GenerateOutput(this._io.pos, 8, "ImageBase", this.ImageBase);
      }

      this.SectionAlignment = this._io.readU4le();
      _root.GenerateOutput(this._io.pos, 4, "SectionAlignment", this.SectionAlignment);
      this.FileAlignment = this._io.readU4le();
      _root.GenerateOutput(this._io.pos, 4, "FileAlignment", this.FileAlignment);
      this.MajorOperatingSystemVersion = this._io.readU2le();
      _root.GenerateOutput(this._io.pos, 2, "MajorOperatingSystemVersion", this.MajorOperatingSystemVersion);
      this.MinorOperatingSystemVersion = this._io.readU2le();
      _root.GenerateOutput(this._io.pos, 2, "MinorOperatingSystemVersion", this.MinorOperatingSystemVersion);
      this.MajorImageVersion = this._io.readU2le();
      _root.GenerateOutput(this._io.pos, 2, "MajorImageVersion", this.MajorImageVersion);
      this.MinorImageVersion = this._io.readU2le();
      _root.GenerateOutput(this._io.pos, 2, "MinorImageVersion", this.MinorImageVersion);
      this.MajorSubsystemVersion = this._io.readU2le();
      _root.GenerateOutput(this._io.pos, 2, "MajorSubsystemVersion", this.MajorSubsystemVersion);
      this.MinorSubsystemVersion = this._io.readU2le();
      _root.GenerateOutput(this._io.pos, 2, "MinorSubsystemVersion", this.MinorSubsystemVersion);
      this.Reserved1 = this._io.readU4le();
      _root.GenerateOutput(this._io.pos, 4, "Reserved1", this.Reserved1);
      this.SizeOfImage = this._io.readU4le();
      _root.GenerateOutput(this._io.pos, 4, "SizeOfImage", this.SizeOfImage);
      this.SizeOfHeaders = this._io.readU4le();
      _root.GenerateOutput(this._io.pos, 4, "SizeOfHeaders", this.SizeOfHeaders);
      this.CheckSum = this._io.readU4le();
      _root.GenerateOutput(this._io.pos, 4, "CheckSum", this.CheckSum);
      this.Subsystem = this._io.readU2le();
      _root.GenerateOutput(this._io.pos, 2, "Subsystem", this.Subsystem);
      this.DllCharacteristics = this._io.readU2le();
      _root.GenerateOutput(this._io.pos, 2, "DllCharacteristics", this.DllCharacteristics);
      if (this.Magic == 267) {
        this.SizeOfStackReserve = this._io.readU4le();
        _root.GenerateOutput(this._io.pos, 4, "SizeOfStackReserve", this.SizeOfStackReserve);
      }
      if (this.Magic == 523) {
        this.SizeOfStackReserve = this._io.readU8le();
        _root.GenerateOutput(this._io.pos, 8, "SizeOfStackReserve", this.SizeOfStackReserve);
      }
      if (this.Magic == 267) {
        this.SizeOfStackCommit = this._io.readU4le();
        _root.GenerateOutput(this._io.pos, 4, "SizeOfStackCommit", this.SizeOfStackCommit);
      }
      if (this.Magic == 523) {
        this.SizeOfStackCommit = this._io.readU8le();
        _root.GenerateOutput(this._io.pos, 8, "SizeOfStackCommit", this.SizeOfStackCommit);
      }
      if (this.Magic == 267) {
        this.SizeOfHeapReserve = this._io.readU4le();
        _root.GenerateOutput(this._io.pos, 4, "SizeOfHeapReserve", this.SizeOfHeapReserve);
      }
      if (this.Magic == 523) {
        this.SizeOfHeapReserve = this._io.readU8le();
        _root.GenerateOutput(this._io.pos, 8, "SizeOfHeapReserve", this.SizeOfHeapReserve);
      }
      if (this.Magic == 267) {
        this.SizeOfHeapCommit = this._io.readU4le();
        _root.GenerateOutput(this._io.pos, 4, "SizeOfHeapCommit", this.SizeOfHeapCommit);
      }
      if (this.Magic == 523) {
        this.SizeOfHeapCommit = this._io.readU8le();
        _root.GenerateOutput(this._io.pos, 8, "SizeOfHeapCommit", this.SizeOfHeapCommit);
      }
      this.LoaderFlags = this._io.readU4le();
      _root.GenerateOutput(this._io.pos, 4, "LoaderFlags", this.LoaderFlags);
      this.NumberOfRvaAndSizes = this._io.readU4le();
      _root.GenerateOutput(this._io.pos, 4, "NumberOfRvaAndSizes", this.NumberOfRvaAndSizes);
    }

    return IMAGE_OPTIONAL_HEADER;
  })();

  var OptionalHeaderDataDirs = (function() {
    function OptionalHeaderDataDirs(_io, _parent, _root) {
      this._io = _io;
      this._parent = _parent;
      this._root = _root || this;

      this.exportTable = new DataDir(this._io, this, this._root);
      this.importTable = new DataDir(this._io, this, this._root);
      this.resourceTable = new DataDir(this._io, this, this._root);
      this.exceptionTable = new DataDir(this._io, this, this._root);
      this.certificateTable = new DataDir(this._io, this, this._root);
      this.baseRelocationTable = new DataDir(this._io, this, this._root);
      this.debug = new DataDir(this._io, this, this._root);
      this.architecture = new DataDir(this._io, this, this._root);
      this.globalPtr = new DataDir(this._io, this, this._root);
      this.tlsTable = new DataDir(this._io, this, this._root);
      this.loadConfigTable = new DataDir(this._io, this, this._root);
      this.boundImport = new DataDir(this._io, this, this._root);
      this.iat = new DataDir(this._io, this, this._root);
      this.delayImportDescriptor = new DataDir(this._io, this, this._root);
      this.clrRuntimeHeader = new DataDir(this._io, this, this._root);
    }

    return OptionalHeaderDataDirs;
  })();

  var DataDir = (function() {
    function DataDir(_io, _parent, _root) {
      this._io = _io;
      this._parent = _parent;
      this._root = _root || this;

      this.virtualAddress = this._io.readU4le();
      this.size = this._io.readU4le();
    }

    return DataDir;
  })();

  var OptionalHeader = (function() {
    function OptionalHeader(_io, _parent, _root) {
      this._io = _io;
      this._parent = _parent;
      this._root = _root || this;

      this.IMAGE_OPTIONAL_HEADER = new IMAGE_OPTIONAL_HEADER(this._io, this, this._root);
      this.dataDirs = new OptionalHeaderDataDirs(this._io, this, this._root);
    }

    return OptionalHeader;
  })();

  var Section = (function() {
    function Section(_io, _parent, _root) {
      this._io = _io;
      this._parent = _parent;
      this._root = _root || this;

      _root.GenerateHeader("[IMAGE_SECTION_HEADER]");

      this.Name = this._io.readStrByteLimit(8, "UTF-8");
      _root.GenerateOutput(this._io.pos, 8, "Name", this.Name);
      this.Misc = this._io.readU4le();
      _root.GenerateOutput(this._io.pos -4, 0, "Misc", this.Misc);
      this.Misc_PhysicalAddress = this.Misc;
      _root.GenerateOutput(this._io.pos-4, 0, "Misc_PhysicalAddress", this.Misc_PhysicalAddress);
      this.Misc_VirtualSize = this.Misc;
      _root.GenerateOutput(this._io.pos, 4, "Misc_VirtualSize", this.Misc_VirtualSize);
      this.VirtualAddress = this._io.readU4le();
      _root.GenerateOutput(this._io.pos, 4, "VirtualAddress", this.VirtualAddress);
      this.SizeOfRawData = this._io.readU4le();
      _root.GenerateOutput(this._io.pos, 4, "SizeOfRawData", this.SizeOfRawData);
      this.PointerToRawData = this._io.readU4le();
      _root.GenerateOutput(this._io.pos, 4, "PointerToRawData", this.PointerToRawData);
      this.PointerToRelocations = this._io.readU4le();
      _root.GenerateOutput(this._io.pos, 4, "PointerToRelocations", this.PointerToRelocations);
      this.PointerToLinenumbers = this._io.readU4le();
      _root.GenerateOutput(this._io.pos, 4, "PointerToLinenumbers", this.PointerToLinenumbers);
      this.NumberOfRelocations = this._io.readU2le();
      _root.GenerateOutput(this._io.pos, 2, "NumberOfRelocations", this.NumberOfRelocations);
      this.NumberOfLinenumbers = this._io.readU2le();
      _root.GenerateOutput(this._io.pos, 2, "NumberOfLinenumbers", this.NumberOfLinenumbers);
      this.Characteristics = this._io.readU4le();
      _root.GenerateOutput(this._io.pos, 4, "Characteristics", this.Characteristics);

    }
    Object.defineProperty(Section.prototype, 'body', {
      get: function() {
        if (this._m_body !== undefined)
          return this._m_body;
        var _pos = this._io.pos;
        this._io.seek(this.PointerToRawData);
        this._m_body = this._io.readBytes(this.SizeOfRawData);
        this._io.seek(_pos);
        return this._m_body;
      }
    });
    Object.defineProperty(Section.prototype, 'directoryEntryImport', {
      get: function() {
        if (this._m_directoryEntryImport !== undefined)
          return this._m_directoryEntryImport;
        var _pos = this._io.pos;
        this._io.seek(((this._parent.optionalHeader.dataDirs.importTable.virtualAddress - this.VirtualAddress) + this.pointerToRawData));
        if (this.VirtualAddress <= this._parent.optionalHeader.dataDirs.importTable.virtualAddress && (this.VirtualAddress + this.Misc_VirtualSize) >= this._parent.optionalHeader.dataDirs.importTable.virtualAddress) {
          this._m_directoryEntryImport = this._io.readBytes(this._parent.optionalHeader.IMAGE_OPTIONAL_HEADER.SectionAlignment);
        }
        this._io.seek(_pos);
        return this._m_directoryEntryImport;
      }
    });

    return Section;
  })();

  var IMAGE_DOS_HEADER = (function() {
    function IMAGE_DOS_HEADER(_io, _parent, _root) {
      this._io = _io;
      this._parent = _parent;
      this._root = _root || this;
      _root.GenerateHeader("----------DOS_HEADER----------");
      _root.GenerateHeader("");
      _root.GenerateHeader("[IMAGE_DOS_HEADER]");
      this.e_magic = this._io.ensureFixedContents([77, 90]);
      _root.GenerateOutput(this._io.pos, 2, "e_magic", this.e_magic);
      this.e_cblp = this._io.readU2le();
      _root.GenerateOutput(this._io.pos, 2, "e_cblp", this.e_cblp);
      this.e_cp = this._io.readU2le();
      _root.GenerateOutput(this._io.pos, 2, "e_cp", this.e_cp);
      this.e_crlc = this._io.readU2le();
      _root.GenerateOutput(this._io.pos, 2, "e_crlc", this.e_crlc);
      this.e_cparhdr = this._io.readU2le();
      _root.GenerateOutput(this._io.pos, 2, "e_cparhdr", this.e_cparhdr);
      this.e_minalloc = this._io.readU2le();
      _root.GenerateOutput(this._io.pos, 2, "e_minalloc", this.e_minalloc);
      this.e_maxalloc = this._io.readU2le();
      _root.GenerateOutput(this._io.pos, 2, "e_maxalloc", this.e_maxalloc);
      this.e_ss = this._io.readU2le();
      _root.GenerateOutput(this._io.pos, 2, "e_ss", this.e_ss);
      this.e_sp = this._io.readU2le();
      _root.GenerateOutput(this._io.pos, 2, "e_sp", this.e_sp);
      this.e_csum = this._io.readU2le();
      _root.GenerateOutput(this._io.pos, 2, "e_csum", this.e_csum);
      this.e_ip = this._io.readU2le();
      _root.GenerateOutput(this._io.pos, 2, "e_ip", this.e_ip);
      this.e_cs = this._io.readU2le();
      _root.GenerateOutput(this._io.pos, 2, "e_cs", this.e_cs);
      this.e_lfarlc = this._io.readU2le();
      _root.GenerateOutput(this._io.pos, 2, "e_lfarlc", this.e_lfarlc);
      this.e_ovno = this._io.readU2le();
      _root.GenerateOutput(this._io.pos, 2, "e_ovno", this.e_ovno);
      this.e_res = this._io.readBytes(8);
      _root.GenerateOutput(this._io.pos, 8, "e_res", this.e_res);
      this.e_oemid = this._io.readU2le();
      _root.GenerateOutput(this._io.pos, 2, "e_oemid", this.e_oemid);
      this.e_oeminfo = this._io.readU2le();
      _root.GenerateOutput(this._io.pos, 2, "e_oeminfo", this.e_oeminfo);
      this.e_res2 = this._io.readBytes(20);
      _root.GenerateOutput(this._io.pos, 20, "e_res2", this.e_res2);
      this.e_lfanew = this._io.readU4le();
      _root.GenerateOutput(this._io.pos, 4, "e_lfanew", this.e_lfanew);
    }

    return IMAGE_DOS_HEADER;
  })();

  var IMAGE_FILE_HEADER = (function() {
    IMAGE_FILE_HEADER.MachineType = Object.freeze({
      'IMAGE_FILE_MACHINE_UNKNOWN':   0,
      'IMAGE_FILE_MACHINE_I386':      332,
      'IMAGE_FILE_MACHINE_R3000':     0x0162,
      'IMAGE_FILE_MACHINE_R4000':     358,
      'IMAGE_FILE_MACHINE_R10000':    0x0168,
      'IMAGE_FILE_MACHINE_WCEMIPSV2': 361,
      'IMAGE_FILE_MACHINE_ALPHA':     0x0184,
      'IMAGE_FILE_MACHINE_SH3':       418,
      'IMAGE_FILE_MACHINE_SH3DSP':    419,
      'IMAGE_FILE_MACHINE_SH3E':      0x01a4,
      'IMAGE_FILE_MACHINE_SH4':       422,
      'IMAGE_FILE_MACHINE_SH5':       424,
      'IMAGE_FILE_MACHINE_ARM':       0x01c0,
      'IMAGE_FILE_MACHINE_THUMB':     0x01c2,
      'IMAGE_FILE_MACHINE_ARMNT':     0x01c4,
      'IMAGE_FILE_MACHINE_AM33':      467,
      'IMAGE_FILE_MACHINE_POWERPC':   496,
      'IMAGE_FILE_MACHINE_POWERPCFP': 497,
      'IMAGE_FILE_MACHINE_IA64':      512,
      'IMAGE_FILE_MACHINE_MIPS16':    614,
      'IMAGE_FILE_MACHINE_ALPHA64':   870,
      'IMAGE_FILE_MACHINE_AXP64':     0x0284,
      'IMAGE_FILE_MACHINE_MIPSFPU':   1126,
      'IMAGE_FILE_MACHINE_MIPSFPU16': 0x0466,
      'IMAGE_FILE_MACHINE_TRICORE':   0x0520,
      'IMAGE_FILE_MACHINE_CEF':       0x0cef,
      'IMAGE_FILE_MACHINE_EBC':       3772,
      'IMAGE_FILE_MACHINE_RISCV32':   20530,
      'IMAGE_FILE_MACHINE_RISCV64':   20580,
      'IMAGE_FILE_MACHINE_RISCV128':  20776,
      'IMAGE_FILE_MACHINE_AMD64':     34404,
      'IMAGE_FILE_MACHINE_M32R':      36929,
      'IMAGE_FILE_MACHINE_CEE':       0xc0ee
    });

    function IMAGE_FILE_HEADER(_io, _parent, _root) {
      this._io = _io;
      this._parent = _parent;
      this._root = _root || this;
      _root.GenerateHeader("");
      _root.GenerateHeader("----------FILE_HEADER----------");
      _root.GenerateHeader("");
      _root.GenerateHeader("[IMAGE_FILE_HEADER]");
      this.Machine = this._io.readU2le();
      _root.GenerateOutput(this._io.pos, 2, "Machine", this.Machine);
      this.NumberOfSections = this._io.readU2le();
      _root.GenerateOutput(this._io.pos, 2, "NumberOfSections", this.NumberOfSections);
      this.TimeDateStamp = this._io.readU4le();
      _root.GenerateOutput(this._io.pos, 4, "TimeDateStamp", this.TimeDateStamp);
      this.PointerToSymbolTable = this._io.readU4le();
      _root.GenerateOutput(this._io.pos, 4, "PointerToSymbolTable", this.PointerToSymbolTable);
      this.NumberOfSymbols = this._io.readU4le();
      _root.GenerateOutput(this._io.pos, 4, "NumberOfSymbols", this.NumberOfSymbols);
      this.SizeOfOptionalHeader = this._io.readU2le();
      _root.GenerateOutput(this._io.pos, 2, "SizeOfOptionalHeader", this.SizeOfOptionalHeader);
      this.Characteristics = this._io.readU2le();
      _root.GenerateOutput(this._io.pos, 2, "Characteristics", this.Characteristics);
    }

    return IMAGE_FILE_HEADER;
  })();
  function GenerateConsoleOutput(line, pefile){
    pefile.PECONSOLE += line +'\r\n';
  }

  function FindImports(pefile){
    var array = [];
    var directory_entry_import = [];
    var directory_entry_import_addr = [];
    if(pefile.optionalHeader.dataDirs.importTable){
      var idata = pefile.optionalHeader.dataDirs.importTable.virtualAddress;

      var idata_size = pefile.optionalHeader.dataDirs.importTable.size;
      if(idata_size){
        for(i = 0; i < pefile.sections.length; i++){
          //console.log("MD5:", md5(body));
          //console.log("SHA2:", sha256(body));
          //console.log("ssdeep:", ssdeep.digest(body));
          //console.log(body);
          //console.log(pefile.sections[i]);
          if(pefile.sections[i].VirtualAddress <= idata
            &&  (pefile.sections[i].VirtualAddress + pefile.sections[i].Misc_VirtualSize) >= idata ){
              console.log("Import data in ", pefile.sections[i].Name, 'section');
              var pointer = (parseInt(pefile.sections[i].PointerToRawData / 0x200)) * 0x200;
              var va = pefile.sections[i].VirtualAddress;
              if (pefile.optionalHeader.IMAGE_OPTIONAL_HEADER.SectionAlignment && (idata % pefile.optionalHeader.IMAGE_OPTIONAL_HEADER.SectionAlignment)){
                valll = pefile.optionalHeader.IMAGE_OPTIONAL_HEADER.SectionAlignment * ( parseInt(va / pefile.optionalHeader.IMAGE_OPTIONAL_HEADER.SectionAlignment) )
                console.log("Something weird?", va, 'new', valll);
                //va = pefile.optionalHeader.IMAGE_OPTIONAL_HEADER.SectionAlignment * ( parseInt(va / pefile.optionalHeader.IMAGE_OPTIONAL_HEADER.SectionAlignment) )
              }
              idata_raw = GetOffset(idata, va, pefile.sections[i].PointerToRawData, pefile);
              console.log("Import table at:", idata_raw);
              pefile._io.seek(idata_raw);
              //pefile._io.pos = pefile._io.pos;
              var read_size = 0;
              while(read_size < idata_size){
                var position = pefile._io.pos;
                var original_first_thunk = pefile._io.readU4le();
                var time_date_stamp = pefile._io.readU4le()
                var forwarder_chain = pefile._io.readU4le()
                var name = pefile._io.readU4le();
                var first_thunk = pefile._io.readU4le()
                if(original_first_thunk != 0 && first_thunk != 0){

                  var addresses = {
                    OriginalFirstThunk: "0x"+ (position).toString(16).toUpperCase(),
                    Characteristics: "0x"+ (position).toString(16).toUpperCase(),
                    TimeDateStamp: "0x"+ (position+4).toString(16).toUpperCase(),
                    ForwarderChain: "0x"+ (position+8).toString(16).toUpperCase(),
                    Name: "0x"+ (position+12).toString(16).toUpperCase(),
                    FirstThunk: "0x"+ (position+16).toString(16).toUpperCase()
                  };
                  var values = {
                    OriginalFirstThunk: original_first_thunk,
                    Characteristics: original_first_thunk,
                    TimeDateStamp: time_date_stamp,
                    ForwarderChain: forwarder_chain,
                    Name: name,
                    FirstThunk: first_thunk
                  };

                  var IMAGE_IMPORT_DESCRIPTOR = {
                    OriginalFirstThunk: { Address: addresses.OriginalFirstThunk, Value: values.OriginalFirstThunk},
                    Characteristics: { Address: addresses.Characteristics, Value: values.Characteristics},
                    TimeDateStamp: { Address: addresses.TimeDateStamp, Value: values.TimeDateStamp},
                    ForwarderChain: { Address: addresses.ForwarderChain, Value: values.ForwarderChain},
                    Name: { Address: addresses.Name, Value: values.Name},
                    FirstThunk: { Address: addresses.FirstThunk, Value: values.FirstThunk},
                    Imports: []
                  }

                  GenerateConsoleOutput("", pefile);
                  GenerateConsoleOutput("[IMAGE_IMPORT_DESCRIPTOR]", pefile);
                  GenerateConsoleOutput(addresses.OriginalFirstThunk  + "     0x0   OriginalFirstThunk:            " + "0x"+values.OriginalFirstThunk.toString(16).toUpperCase(), pefile);
                  GenerateConsoleOutput(addresses.Characteristics     + "     0x0   Characteristics:               " + "0x"+values.Characteristics.toString(16).toUpperCase(), pefile);
                  GenerateConsoleOutput(addresses.TimeDateStamp       + "     0x4   TimeDateStamp:                 " + "0x"+values.TimeDateStamp.toString(16).toUpperCase(), pefile);
                  GenerateConsoleOutput(addresses.ForwarderChain      + "     0x8   ForwarderChain:                " + "0x"+values.ForwarderChain.toString(16).toUpperCase(), pefile);
                  GenerateConsoleOutput(addresses.Name                + "     0xC   Name:                          " + "0x"+values.Name.toString(16).toUpperCase(), pefile);
                  GenerateConsoleOutput(addresses.FirstThunk          + "     0x10  FirstThunk:                    " + "0x"+values.FirstThunk.toString(16).toUpperCase(), pefile);
                  GenerateConsoleOutput("", pefile);


                  /*
                  0x6B7C     0x0   OriginalFirstThunk:            0x8844
                  0x6B7C     0x0   Characteristics:               0x8844
                  0x6B80     0x4   TimeDateStamp:                 0x0        [Thu Jan  1 00:00:00 1970 UTC]
                  0x6B84     0x8   ForwarderChain:                0x0
                  0x6B88     0xC   Name:                          0x939A
                  0x6B8C     0x10  FirstThunk:                    0x82A0
                  */
                  //console.log()
                  //console.log(addresses);

                  directory_entry_import_addr.push(addresses);
                  directory_entry_import.push(values);
                  pefile.IMPORT_SECTION_VIRTUAL_ADDRESS = pefile.sections[i].VirtualAddress;
                  pefile.IMPORT_SECTION_POINTER_TO_RAW = pefile.sections[i].PointerToRawData;

                  var raw_name = GetOffset(name, pefile.sections[i].VirtualAddress, pefile.sections[i].PointerToRawData, pefile);
                  var import_name = GetImageImportDescriptorName(raw_name, name, pefile);
                  var raw_original = GetOffset(original_first_thunk, pefile.sections[i].VirtualAddress, pefile.sections[i].PointerToRawData, pefile);
                  var original_pointers = ReadOriginalThunk(raw_original, name, pefile);
                  var raw_first = GetOffset(first_thunk, pefile.sections[i].VirtualAddress, pefile.sections[i].PointerToRawData, pefile);
                  var first_pointers = ReadFirstThunk(raw_first, name, pefile);
                  for(g=0; g<original_pointers.values.length; g++){
                    if(isNaN(first_pointers.values[g])){
                      var string = import_name + "." + first_pointers.values[g] + " Hint["+original_pointers.values[g] + "]";
                      IMAGE_IMPORT_DESCRIPTOR.Imports.push(string)
                      GenerateConsoleOutput(string, pefile);
                      SetImpString(import_name, first_pointers.values[g], pefile);

                    } else {
                      var ord_lookup = undefined;
                      if(import_name.toUpperCase() == "oleauth32.dll".toUpperCase()){
                        ord_lookup = oleauth32_ord_names[first_pointers.values[g]] ? oleauth32_ord_names[first_pointers.values[g]] : undefined;
                      }
                      if(import_name.toUpperCase() == "WS2_32.dll".toUpperCase()){
                        ord_lookup = ws2_32_ord_names[first_pointers.values[g]] ? ws2_32_ord_names[first_pointers.values[g]] : undefined;
                      }
                      if(ord_lookup){
                        var string = import_name + "." + ord_lookup + " Hint["+original_pointers.values[g] + "]";
                        IMAGE_IMPORT_DESCRIPTOR.Imports.push(string)
                        GenerateConsoleOutput(string, pefile);
                        SetImpString(import_name, ord_lookup, pefile);
                      } else {
                        var string = import_name + " Ordinal[" + first_pointers.values[g] + "] (Imported by Ordinal)";
                        IMAGE_IMPORT_DESCRIPTOR.Imports.push(string)
                        SetImpString(import_name, "ord"+first_pointers.values[g], pefile);
                        GenerateConsoleOutput(string, pefile);
                      }

                    }


                  }
                  array.push(IMAGE_IMPORT_DESCRIPTOR);

                } else {
                  console.log("Uhoh!");
                }
               read_size += 20;
            }
          }
        }
        GenerateImpHash(pefile)
        GenerateImpDeep(pefile)
        GenerateConsoleOutput("", pefile);
        GenerateConsoleOutput("Imphash: " + pefile.IMPHASH, pefile);
        GenerateConsoleOutput("Impdeep: " + pefile.IMPDEEP, pefile);
        //GenerateConsoleOutput("Import String: " + pefile.IMPORT_STRING,pefile)
      }
    }
    return array;
  }


  function PerformAllHashing(){
    GenerateConsoleOutput("MD5     hash: " + this.sections[i]["MD5"]);
    GenerateConsoleOutput("SHA-256 hash: " + this.sections[i]["SHA256"]);
    GenerateConsoleOutput("ssdeep  hash: " + this.sections[i]["ssdeep"]);
    this.GenerateHeader("");
  }

  function GetOffset(va, va_offset, pointer, pefile){

    console.log("Inbound VA:", va, 'Offset:', va_offset, 'Pointer:', pointer)
    var rva = (va - va_offset) + pointer;
    if(rva < 0){

      va_offset = GetOffsetFromVA(va, pefile, va_offset);
      //console.log("")
      rva = (va - va_offset) + pointer;
      if(rva < 0) rva = va_offset;
      console.log("RAW:", va, 'RVA:', rva)
      console.log("READJUST:", va, 'RVA:', rva);


    }
    console.log("VA:", '0x'+parseInt(va,16), 'RVA:', '0x'+parseInt(rva,16))
    return rva;
  }

  function GetOffsetFromVA(va, pefile, last){
    var offset = last;
    console.log("Get Offset")
    for(t = 0; t < pefile.sections.length; t++){
      //console.log("MD5:", md5(body));
      //console.log("SHA2:", sha256(body));
      //console.log("ssdeep:", ssdeep.digest(body));
      //console.log(body);
      //console.log(pefile.sections[i]);
      if(pefile.sections[i].VirtualAddress <= va  &&  (pefile.sections[i].VirtualAddress + pefile.sections[i].Misc_VirtualSize) >= va ){
          offset = pefile.sections[t].PointerToRawData;
          console.log("New offset:", offset)
      }
    }
    return offset;
  }

  function GetImageImportDescriptorName(raw_location, virtual_address, pefile){
    var before_pos = pefile._io.pos;
    pefile._io.seek(raw_location);
    var name = pefile._io.readStrz('utf-8', '0');
    //console.log('Import Name - VA:', virtual_address, '0x'+parseInt(virtual_address,16), name)
    //console.log('Import Name - RVA:', raw_location, '0x'+parseInt(raw_location,16), name);
    pefile._io.seek(before_pos);
    return name;
  }

  function ReadOriginalThunk(raw_location, virtual_address, pefile){
    var before_pos = pefile._io.pos;
    pefile._io.seek(raw_location);
    var array_of_pointers = [];
    var array_of_values = [];
    var pointer;
    var continue_loop = true;
    var previous_pointer = 0;
    var clear_previous = false;
    while(continue_loop){
      pointer1 = pefile._io.readU2le();
      pointer2 = pefile._io.readU2le();
      console.log("pointers:", pointer1, pointer1.toString(16), "prev:", pointer2,pointer2 ? pointer2.toString(16): pointer2 );
      if(pointer1 == 0 && pointer2 == 0) {
        continue_loop = false;
      }
      if(continue_loop && (pointer1 != 0) ) {
        if(pointer != 32768 && previous_pointer != 32768){
          var dothispointer;
          if(pointer2 && pointer2 != 0 ){
            var temp = pointer2 << 16;
            console.log("Adding previous pointer:", temp, pointer1)
            dothispointer = temp + pointer1;
            clear_previous = true;

          } else {
            dothispointer = pointer1;
          }
          pointer_value = ReadHintFromPointer(dothispointer, pefile);
          array_of_pointers.push(pointer);
          array_of_values.push(pointer_value);

        }
      }
    }
    pefile._io.seek(before_pos);
    return {pointers: array_of_pointers, values: array_of_values};
  }


  function ReadFirstThunk(raw_location, virtual_address, pefile){
    var before_pos = pefile._io.pos;
    pefile._io.seek(raw_location);
    var array_of_pointers = [];
    var array_of_values = [];
    var pointer;
    var continue_loop = true;
    var previous_pointer = 0;
    var clear_previous = false;
    while(continue_loop){
      pointer1 = pefile._io.readU2le();
      pointer2 = pefile._io.readU2le();
      console.log("pointers:", pointer1, pointer1.toString(16), "prev:", pointer2,pointer2 ? pointer2.toString(16): pointer2 );
      if(pointer1 == 0 && pointer2 == 0) {
        continue_loop = false;
      }
      if(continue_loop && (pointer1 != 0) ) {
        if(pointer != 32768 && previous_pointer != 32768){
          var dothispointer;
          if(pointer2 && pointer2 != 0 ){
            var temp = pointer2 << 16;
            console.log("Adding previous pointer:", temp, pointer1)
            dothispointer = temp + pointer1;
            clear_previous = true;

          } else {
            dothispointer = pointer1;
          }
          pointer_value = ReadFunctionFromPointer(dothispointer, pefile);
          array_of_pointers.push(dothispointer);
          array_of_values.push(pointer_value);

        }
      }
    }
    //console.log('Import array of pointers - VA:', virtual_address, '0x'+virtual_address.toString(16))
    //console.log('Import array of pointers - RVA:', raw_location, '0x'+raw_location.toString(16), JSON.stringify(array_of_pointers));
    //console.log('Functions:', JSON.stringify(array_of_values));
    pefile._io.seek(before_pos);
    return {pointers: array_of_pointers, values: array_of_values};
  }




  /*
  function OldReadOriginalThunk(raw_location, virtual_address, pefile){
    var before_pos = pefile._io.pos;
    pefile._io.seek(raw_location);
    var array_of_pointers = [];
    var array_of_values = [];
    var pointer;
    var continue_loop = true;
    var previous_pointer = undefined;
    var clear_previous = false;
    while(continue_loop){
      pointer = pefile._io.readU2le();
      console.log("pointers:", pointer, pointer.toString(16), "prev:", previous_pointer,previous_pointer ? previous_pointer.toString(16): previous_pointer );
      var previous_pointer
      if(pointer == 0) {
        //console.log("hit null:", pointer);
        if(previous_pointer == 0) continue_loop = false;
      }
      if(continue_loop && (pointer != 0) ) {
        if(pointer != 32768 && previous_pointer != 32768){
          var dothispointer;
          if(previous_pointer && previous_pointer != 0 && previous_pointer != 32768){
            var temp = pointer << 16;
            console.log("Adding previous pointer:", temp, previous_pointer)
            dothispointer = temp + previous_pointer;
            clear_previous = true;
          } else {
            dothispointer = pointer;
          }
          pointer_value = ReadHintFromPointer(dothispointer, pefile);
          array_of_pointers.push(pointer);
          array_of_values.push(pointer_value);
        }
      }
      if(clear_previous){
        clear_previous = false;
        previous_pointer = undefined;
      } else {
        previous_pointer = pointer;

      }
    }
    console.log('Import array of pointers - VA:', virtual_address, '0x'+virtual_address.toString(16))
    //console.log('Import array of pointers - RVA:', raw_location, '0x'+raw_location.toString(16), JSON.stringify(array_of_pointers));
    //console.log('Hints:', JSON.stringify(array_of_values));
    pefile._io.seek(before_pos);
    return {pointers: array_of_pointers, values: array_of_values};
  }


  function OldReadFirstThunk(raw_location, virtual_address, pefile){
    var before_pos = pefile._io.pos;
    pefile._io.seek(raw_location);
    var array_of_pointers = [];
    var array_of_values = [];
    var pointer;
    var continue_loop = true;
    var previous_pointer = 0;
    var clear_previous = false;
    while(continue_loop){
      pointer = pefile._io.readU2le();
      console.log("pointers:", pointer, pointer.toString(16), "prev:", previous_pointer,previous_pointer ? previous_pointer.toString(16): previous_pointer );
      if(pointer == 0) {
        //console.log("hit null:", pointer);
        if(previous_pointer == 0 ) continue_loop = false;
      }
      if(continue_loop && (pointer != 0) ) {
        if(pointer != 32768 && previous_pointer != 32768){
          var dothispointer;
          if(previous_pointer && previous_pointer != 0 ){
            var temp = pointer << 16;
            console.log("Adding previous pointer:", temp, previous_pointer)
            dothispointer = temp + previous_pointer;
            clear_previous = true;

          } else {
            dothispointer = pointer;
          }
          if(previous_pointer == 0){
            pointer_value = ReadFunctionFromPointer(dothispointer, pefile);
            array_of_pointers.push(dothispointer);
            array_of_values.push(pointer_value);
          }
        }
      }
      if(clear_previous){
        clear_previous = false;
        previous_pointer = 0;
      } else {
        previous_pointer = pointer;

      }
    }
    //console.log('Import array of pointers - VA:', virtual_address, '0x'+virtual_address.toString(16))
    //console.log('Import array of pointers - RVA:', raw_location, '0x'+raw_location.toString(16), JSON.stringify(array_of_pointers));
    //console.log('Functions:', JSON.stringify(array_of_values));
    pefile._io.seek(before_pos);
    return {pointers: array_of_pointers, values: array_of_values};
  }
  */

  function ReadHintFromPointer(pointer, pefile){
    console.log("ReadHintFromPointer:", pointer, pointer.toString(16))
    var before_pos = pefile._io.pos;
    var raw_location = GetOffset(pointer, pefile.IMPORT_SECTION_VIRTUAL_ADDRESS, pefile.IMPORT_SECTION_POINTER_TO_RAW, pefile);
    console.log("ReadHintFromPointer raw_location:", raw_location, raw_location.toString(16))
    pefile._io.seek(raw_location);

    var value = pefile._io.readU2le();
    console.log("loc", raw_location, ", val:", value.toString(16).toUpperCase(), 'pointer:', pointer.toString(16).toUpperCase())
    pefile._io.seek(before_pos);
    return value;
  }

  function ReadFunctionFromPointer(pointer, pefile){
    console.log("ReadFunctionFromPointer:", pointer, pointer.toString(16))
    var before_pos = pefile._io.pos;
    var value;
    if(pointer > 32768){
      var raw_location = GetOffset(pointer, pefile.IMPORT_SECTION_VIRTUAL_ADDRESS, pefile.IMPORT_SECTION_POINTER_TO_RAW, pefile);
      raw_location = raw_location;
      pefile._io.seek(raw_location);
      var check_ordinal = pefile._io.readU2le();
      console.log("ORD: loc", raw_location.toString(16).toUpperCase(), ", ord:", check_ordinal, check_ordinal.toString(16).toUpperCase(), 'pointer:', pointer.toString(16).toUpperCase())

      var is_ordinal = (check_ordinal > 32768) ? true : false;
      if(is_ordinal){
        /*

        */
        value = pefile._io.readStrz('ASCII', '0');;
        console.log("check ordinal: " + check_ordinal)
      } else {
        value = pefile._io.readStrz('ASCII', '0');
      }
      pefile._io.seek(before_pos);
      return value;
    } else {
      pointer = pointer & 0x0000FFFF;
      return pointer;
    }
  }

  function SetImpString(lib, func, pefile){
    var break_ext = lib.toLowerCase().split(".")
    var noex = break_ext[0];
    if(break_ext[1] == 'ocx' || break_ext[1] == 'sys' || break_ext[1] == 'dll'){
      if(pefile.IMPORT_STRING != "") pefile.IMPORT_STRING += ",";
      pefile.IMPORT_STRING += noex + "." +func.toLowerCase()
    }
  }

  function GenerateImpHash(pefile){
    pefile.IMPHASH = md5(pefile.IMPORT_STRING);
  }

  function GenerateImpDeep(pefile){
    pefile.IMPDEEP = ssdeep.digest(pefile.IMPORT_STRING);
  }

  oleauth32_ord_names = {
      2: 'SysAllocString',
      3: 'SysReAllocString',
      4: 'SysAllocStringLen',
      5: 'SysReAllocStringLen',
      6: 'SysFreeString',
      7: 'SysStringLen',
      8: 'VariantInit',
      9: 'VariantClear',
      10: 'VariantCopy',
      11: 'VariantCopyInd',
      12: 'VariantChangeType',
      13: 'VariantTimeToDosDateTime',
      14: 'DosDateTimeToVariantTime',
      15: 'SafeArrayCreate',
      16: 'SafeArrayDestroy',
      17: 'SafeArrayGetDim',
      18: 'SafeArrayGetElemsize',
      19: 'SafeArrayGetUBound',
      20: 'SafeArrayGetLBound',
      21: 'SafeArrayLock',
      22: 'SafeArrayUnlock',
      23: 'SafeArrayAccessData',
      24: 'SafeArrayUnaccessData',
      25: 'SafeArrayGetElement',
      26: 'SafeArrayPutElement',
      27: 'SafeArrayCopy',
      28: 'DispGetParam',
      29: 'DispGetIDsOfNames',
      30: 'DispInvoke',
      31: 'CreateDispTypeInfo',
      32: 'CreateStdDispatch',
      33: 'RegisterActiveObject',
      34: 'RevokeActiveObject',
      35: 'GetActiveObject',
      36: 'SafeArrayAllocDescriptor',
      37: 'SafeArrayAllocData',
      38: 'SafeArrayDestroyDescriptor',
      39: 'SafeArrayDestroyData',
      40: 'SafeArrayRedim',
      41: 'SafeArrayAllocDescriptorEx',
      42: 'SafeArrayCreateEx',
      43: 'SafeArrayCreateVectorEx',
      44: 'SafeArraySetRecordInfo',
      45: 'SafeArrayGetRecordInfo',
      46: 'VarParseNumFromStr',
      47: 'VarNumFromParseNum',
      48: 'VarI2FromUI1',
      49: 'VarI2FromI4',
      50: 'VarI2FromR4',
      51: 'VarI2FromR8',
      52: 'VarI2FromCy',
      53: 'VarI2FromDate',
      54: 'VarI2FromStr',
      55: 'VarI2FromDisp',
      56: 'VarI2FromBool',
      57: 'SafeArraySetIID',
      58: 'VarI4FromUI1',
      59: 'VarI4FromI2',
      60: 'VarI4FromR4',
      61: 'VarI4FromR8',
      62: 'VarI4FromCy',
      63: 'VarI4FromDate',
      64: 'VarI4FromStr',
      65: 'VarI4FromDisp',
      66: 'VarI4FromBool',
      67: 'SafeArrayGetIID',
      68: 'VarR4FromUI1',
      69: 'VarR4FromI2',
      70: 'VarR4FromI4',
      71: 'VarR4FromR8',
      72: 'VarR4FromCy',
      73: 'VarR4FromDate',
      74: 'VarR4FromStr',
      75: 'VarR4FromDisp',
      76: 'VarR4FromBool',
      77: 'SafeArrayGetVartype',
      78: 'VarR8FromUI1',
      79: 'VarR8FromI2',
      80: 'VarR8FromI4',
      81: 'VarR8FromR4',
      82: 'VarR8FromCy',
      83: 'VarR8FromDate',
      84: 'VarR8FromStr',
      85: 'VarR8FromDisp',
      86: 'VarR8FromBool',
      87: 'VarFormat',
      88: 'VarDateFromUI1',
      89: 'VarDateFromI2',
      90: 'VarDateFromI4',
      91: 'VarDateFromR4',
      92: 'VarDateFromR8',
      93: 'VarDateFromCy',
      94: 'VarDateFromStr',
      95: 'VarDateFromDisp',
      96: 'VarDateFromBool',
      97: 'VarFormatDateTime',
      98: 'VarCyFromUI1',
      99: 'VarCyFromI2',
      100: 'VarCyFromI4',
      101: 'VarCyFromR4',
      102: 'VarCyFromR8',
      103: 'VarCyFromDate',
      104: 'VarCyFromStr',
      105: 'VarCyFromDisp',
      106: 'VarCyFromBool',
      107: 'VarFormatNumber',
      108: 'VarBstrFromUI1',
      109: 'VarBstrFromI2',
      110: 'VarBstrFromI4',
      111: 'VarBstrFromR4',
      112: 'VarBstrFromR8',
      113: 'VarBstrFromCy',
      114: 'VarBstrFromDate',
      115: 'VarBstrFromDisp',
      116: 'VarBstrFromBool',
      117: 'VarFormatPercent',
      118: 'VarBoolFromUI1',
      119: 'VarBoolFromI2',
      120: 'VarBoolFromI4',
      121: 'VarBoolFromR4',
      122: 'VarBoolFromR8',
      123: 'VarBoolFromDate',
      124: 'VarBoolFromCy',
      125: 'VarBoolFromStr',
      126: 'VarBoolFromDisp',
      127: 'VarFormatCurrency',
      128: 'VarWeekdayName',
      129: 'VarMonthName',
      130: 'VarUI1FromI2',
      131: 'VarUI1FromI4',
      132: 'VarUI1FromR4',
      133: 'VarUI1FromR8',
      134: 'VarUI1FromCy',
      135: 'VarUI1FromDate',
      136: 'VarUI1FromStr',
      137: 'VarUI1FromDisp',
      138: 'VarUI1FromBool',
      139: 'VarFormatFromTokens',
      140: 'VarTokenizeFormatString',
      141: 'VarAdd',
      142: 'VarAnd',
      143: 'VarDiv',
      144: 'DllCanUnloadNow',
      145: 'DllGetClassObject',
      146: 'DispCallFunc',
      147: 'VariantChangeTypeEx',
      148: 'SafeArrayPtrOfIndex',
      149: 'SysStringByteLen',
      150: 'SysAllocStringByteLen',
      151: 'DllRegisterServer',
      152: 'VarEqv',
      153: 'VarIdiv',
      154: 'VarImp',
      155: 'VarMod',
      156: 'VarMul',
      157: 'VarOr',
      158: 'VarPow',
      159: 'VarSub',
      160: 'CreateTypeLib',
      161: 'LoadTypeLib',
      162: 'LoadRegTypeLib',
      163: 'RegisterTypeLib',
      164: 'QueryPathOfRegTypeLib',
      165: 'LHashValOfNameSys',
      166: 'LHashValOfNameSysA',
      167: 'VarXor',
      168: 'VarAbs',
      169: 'VarFix',
      170: 'OaBuildVersion',
      171: 'ClearCustData',
      172: 'VarInt',
      173: 'VarNeg',
      174: 'VarNot',
      175: 'VarRound',
      176: 'VarCmp',
      177: 'VarDecAdd',
      178: 'VarDecDiv',
      179: 'VarDecMul',
      180: 'CreateTypeLib2',
      181: 'VarDecSub',
      182: 'VarDecAbs',
      183: 'LoadTypeLibEx',
      184: 'SystemTimeToVariantTime',
      185: 'VariantTimeToSystemTime',
      186: 'UnRegisterTypeLib',
      187: 'VarDecFix',
      188: 'VarDecInt',
      189: 'VarDecNeg',
      190: 'VarDecFromUI1',
      191: 'VarDecFromI2',
      192: 'VarDecFromI4',
      193: 'VarDecFromR4',
      194: 'VarDecFromR8',
      195: 'VarDecFromDate',
      196: 'VarDecFromCy',
      197: 'VarDecFromStr',
      198: 'VarDecFromDisp',
      199: 'VarDecFromBool',
      200: 'GetErrorInfo',
      201: 'SetErrorInfo',
      202: 'CreateErrorInfo',
      203: 'VarDecRound',
      204: 'VarDecCmp',
      205: 'VarI2FromI1',
      206: 'VarI2FromUI2',
      207: 'VarI2FromUI4',
      208: 'VarI2FromDec',
      209: 'VarI4FromI1',
      210: 'VarI4FromUI2',
      211: 'VarI4FromUI4',
      212: 'VarI4FromDec',
      213: 'VarR4FromI1',
      214: 'VarR4FromUI2',
      215: 'VarR4FromUI4',
      216: 'VarR4FromDec',
      217: 'VarR8FromI1',
      218: 'VarR8FromUI2',
      219: 'VarR8FromUI4',
      220: 'VarR8FromDec',
      221: 'VarDateFromI1',
      222: 'VarDateFromUI2',
      223: 'VarDateFromUI4',
      224: 'VarDateFromDec',
      225: 'VarCyFromI1',
      226: 'VarCyFromUI2',
      227: 'VarCyFromUI4',
      228: 'VarCyFromDec',
      229: 'VarBstrFromI1',
      230: 'VarBstrFromUI2',
      231: 'VarBstrFromUI4',
      232: 'VarBstrFromDec',
      233: 'VarBoolFromI1',
      234: 'VarBoolFromUI2',
      235: 'VarBoolFromUI4',
      236: 'VarBoolFromDec',
      237: 'VarUI1FromI1',
      238: 'VarUI1FromUI2',
      239: 'VarUI1FromUI4',
      240: 'VarUI1FromDec',
      241: 'VarDecFromI1',
      242: 'VarDecFromUI2',
      243: 'VarDecFromUI4',
      244: 'VarI1FromUI1',
      245: 'VarI1FromI2',
      246: 'VarI1FromI4',
      247: 'VarI1FromR4',
      248: 'VarI1FromR8',
      249: 'VarI1FromDate',
      250: 'VarI1FromCy',
      251: 'VarI1FromStr',
      252: 'VarI1FromDisp',
      253: 'VarI1FromBool',
      254: 'VarI1FromUI2',
      255: 'VarI1FromUI4',
      256: 'VarI1FromDec',
      257: 'VarUI2FromUI1',
      258: 'VarUI2FromI2',
      259: 'VarUI2FromI4',
      260: 'VarUI2FromR4',
      261: 'VarUI2FromR8',
      262: 'VarUI2FromDate',
      263: 'VarUI2FromCy',
      264: 'VarUI2FromStr',
      265: 'VarUI2FromDisp',
      266: 'VarUI2FromBool',
      267: 'VarUI2FromI1',
      268: 'VarUI2FromUI4',
      269: 'VarUI2FromDec',
      270: 'VarUI4FromUI1',
      271: 'VarUI4FromI2',
      272: 'VarUI4FromI4',
      273: 'VarUI4FromR4',
      274: 'VarUI4FromR8',
      275: 'VarUI4FromDate',
      276: 'VarUI4FromCy',
      277: 'VarUI4FromStr',
      278: 'VarUI4FromDisp',
      279: 'VarUI4FromBool',
      280: 'VarUI4FromI1',
      281: 'VarUI4FromUI2',
      282: 'VarUI4FromDec',
      283: 'BSTR_UserSize',
      284: 'BSTR_UserMarshal',
      285: 'BSTR_UserUnmarshal',
      286: 'BSTR_UserFree',
      287: 'VARIANT_UserSize',
      288: 'VARIANT_UserMarshal',
      289: 'VARIANT_UserUnmarshal',
      290: 'VARIANT_UserFree',
      291: 'LPSAFEARRAY_UserSize',
      292: 'LPSAFEARRAY_UserMarshal',
      293: 'LPSAFEARRAY_UserUnmarshal',
      294: 'LPSAFEARRAY_UserFree',
      295: 'LPSAFEARRAY_Size',
      296: 'LPSAFEARRAY_Marshal',
      297: 'LPSAFEARRAY_Unmarshal',
      298: 'VarDecCmpR8',
      299: 'VarCyAdd',
      300: 'DllUnregisterServer',
      301: 'OACreateTypeLib2',
      303: 'VarCyMul',
      304: 'VarCyMulI4',
      305: 'VarCySub',
      306: 'VarCyAbs',
      307: 'VarCyFix',
      308: 'VarCyInt',
      309: 'VarCyNeg',
      310: 'VarCyRound',
      311: 'VarCyCmp',
      312: 'VarCyCmpR8',
      313: 'VarBstrCat',
      314: 'VarBstrCmp',
      315: 'VarR8Pow',
      316: 'VarR4CmpR8',
      317: 'VarR8Round',
      318: 'VarCat',
      319: 'VarDateFromUdateEx',
      322: 'GetRecordInfoFromGuids',
      323: 'GetRecordInfoFromTypeInfo',
      325: 'SetVarConversionLocaleSetting',
      326: 'GetVarConversionLocaleSetting',
      327: 'SetOaNoCache',
      329: 'VarCyMulI8',
      330: 'VarDateFromUdate',
      331: 'VarUdateFromDate',
      332: 'GetAltMonthNames',
      333: 'VarI8FromUI1',
      334: 'VarI8FromI2',
      335: 'VarI8FromR4',
      336: 'VarI8FromR8',
      337: 'VarI8FromCy',
      338: 'VarI8FromDate',
      339: 'VarI8FromStr',
      340: 'VarI8FromDisp',
      341: 'VarI8FromBool',
      342: 'VarI8FromI1',
      343: 'VarI8FromUI2',
      344: 'VarI8FromUI4',
      345: 'VarI8FromDec',
      346: 'VarI2FromI8',
      347: 'VarI2FromUI8',
      348: 'VarI4FromI8',
      349: 'VarI4FromUI8',
      360: 'VarR4FromI8',
      361: 'VarR4FromUI8',
      362: 'VarR8FromI8',
      363: 'VarR8FromUI8',
      364: 'VarDateFromI8',
      365: 'VarDateFromUI8',
      366: 'VarCyFromI8',
      367: 'VarCyFromUI8',
      368: 'VarBstrFromI8',
      369: 'VarBstrFromUI8',
      370: 'VarBoolFromI8',
      371: 'VarBoolFromUI8',
      372: 'VarUI1FromI8',
      373: 'VarUI1FromUI8',
      374: 'VarDecFromI8',
      375: 'VarDecFromUI8',
      376: 'VarI1FromI8',
      377: 'VarI1FromUI8',
      378: 'VarUI2FromI8',
      379: 'VarUI2FromUI8',
      401: 'OleLoadPictureEx',
      402: 'OleLoadPictureFileEx',
      411: 'SafeArrayCreateVector',
      412: 'SafeArrayCopyData',
      413: 'VectorFromBstr',
      414: 'BstrFromVector',
      415: 'OleIconToCursor',
      416: 'OleCreatePropertyFrameIndirect',
      417: 'OleCreatePropertyFrame',
      418: 'OleLoadPicture',
      419: 'OleCreatePictureIndirect',
      420: 'OleCreateFontIndirect',
      421: 'OleTranslateColor',
      422: 'OleLoadPictureFile',
      423: 'OleSavePictureFile',
      424: 'OleLoadPicturePath',
      425: 'VarUI4FromI8',
      426: 'VarUI4FromUI8',
      427: 'VarI8FromUI8',
      428: 'VarUI8FromI8',
      429: 'VarUI8FromUI1',
      430: 'VarUI8FromI2',
      431: 'VarUI8FromR4',
      432: 'VarUI8FromR8',
      433: 'VarUI8FromCy',
      434: 'VarUI8FromDate',
      435: 'VarUI8FromStr',
      436: 'VarUI8FromDisp',
      437: 'VarUI8FromBool',
      438: 'VarUI8FromI1',
      439: 'VarUI8FromUI2',
      440: 'VarUI8FromUI4',
      441: 'VarUI8FromDec',
      442: 'RegisterTypeLibForUser',
      443: 'UnRegisterTypeLibForUser',
  };

  ws2_32_ord_names = {
      1: 'accept',
      2: 'bind',
      3: 'closesocket',
      4: 'connect',
      5: 'getpeername',
      6: 'getsockname',
      7: 'getsockopt',
      8: 'htonl',
      9: 'htons',
      10: 'ioctlsocket',
      11: 'inet_addr',
      12: 'inet_ntoa',
      13: 'listen',
      14: 'ntohl',
      15: 'ntohs',
      16: 'recv',
      17: 'recvfrom',
      18: 'select',
      19: 'send',
      20: 'sendto',
      21: 'setsockopt',
      22: 'shutdown',
      23: 'socket',
      24: 'GetAddrInfoW',
      25: 'GetNameInfoW',
      26: 'WSApSetPostRoutine',
      27: 'FreeAddrInfoW',
      28: 'WPUCompleteOverlappedRequest',
      29: 'WSAAccept',
      30: 'WSAAddressToStringA',
      31: 'WSAAddressToStringW',
      32: 'WSACloseEvent',
      33: 'WSAConnect',
      34: 'WSACreateEvent',
      35: 'WSADuplicateSocketA',
      36: 'WSADuplicateSocketW',
      37: 'WSAEnumNameSpaceProvidersA',
      38: 'WSAEnumNameSpaceProvidersW',
      39: 'WSAEnumNetworkEvents',
      40: 'WSAEnumProtocolsA',
      41: 'WSAEnumProtocolsW',
      42: 'WSAEventSelect',
      43: 'WSAGetOverlappedResult',
      44: 'WSAGetQOSByName',
      45: 'WSAGetServiceClassInfoA',
      46: 'WSAGetServiceClassInfoW',
      47: 'WSAGetServiceClassNameByClassIdA',
      48: 'WSAGetServiceClassNameByClassIdW',
      49: 'WSAHtonl',
      50: 'WSAHtons',
      51: 'gethostbyaddr',
      52: 'gethostbyname',
      53: 'getprotobyname',
      54: 'getprotobynumber',
      55: 'getservbyname',
      56: 'getservbyport',
      57: 'gethostname',
      58: 'WSAInstallServiceClassA',
      59: 'WSAInstallServiceClassW',
      60: 'WSAIoctl',
      61: 'WSAJoinLeaf',
      62: 'WSALookupServiceBeginA',
      63: 'WSALookupServiceBeginW',
      64: 'WSALookupServiceEnd',
      65: 'WSALookupServiceNextA',
      66: 'WSALookupServiceNextW',
      67: 'WSANSPIoctl',
      68: 'WSANtohl',
      69: 'WSANtohs',
      70: 'WSAProviderConfigChange',
      71: 'WSARecv',
      72: 'WSARecvDisconnect',
      73: 'WSARecvFrom',
      74: 'WSARemoveServiceClass',
      75: 'WSAResetEvent',
      76: 'WSASend',
      77: 'WSASendDisconnect',
      78: 'WSASendTo',
      79: 'WSASetEvent',
      80: 'WSASetServiceA',
      81: 'WSASetServiceW',
      82: 'WSASocketA',
      83: 'WSASocketW',
      84: 'WSAStringToAddressA',
      85: 'WSAStringToAddressW',
      86: 'WSAWaitForMultipleEvents',
      87: 'WSCDeinstallProvider',
      88: 'WSCEnableNSProvider',
      89: 'WSCEnumProtocols',
      90: 'WSCGetProviderPath',
      91: 'WSCInstallNameSpace',
      92: 'WSCInstallProvider',
      93: 'WSCUnInstallNameSpace',
      94: 'WSCUpdateProvider',
      95: 'WSCWriteNameSpaceOrder',
      96: 'WSCWriteProviderOrder',
      97: 'freeaddrinfo',
      98: 'getaddrinfo',
      99: 'getnameinfo',
      101: 'WSAAsyncSelect',
      102: 'WSAAsyncGetHostByAddr',
      103: 'WSAAsyncGetHostByName',
      104: 'WSAAsyncGetProtoByNumber',
      105: 'WSAAsyncGetProtoByName',
      106: 'WSAAsyncGetServByPort',
      107: 'WSAAsyncGetServByName',
      108: 'WSACancelAsyncRequest',
      109: 'WSASetBlockingHook',
      110: 'WSAUnhookBlockingHook',
      111: 'WSAGetLastError',
      112: 'WSASetLastError',
      113: 'WSACancelBlockingCall',
      114: 'WSAIsBlocking',
      115: 'WSAStartup',
      116: 'WSACleanup',
      151: '__WSAFDIsSet',
      500: 'WEP',
  }

  return Pefile;
})();

// Export for amd environments
if (typeof define === 'function' && define.amd) {
  define('Pefile', [], function() {
    return Pefile;
  });
}

// Export for CommonJS
if (typeof module === 'object' && module && module.exports) {
  module.exports = Pefile;
}
