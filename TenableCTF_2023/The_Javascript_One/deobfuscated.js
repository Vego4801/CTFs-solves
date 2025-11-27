var operations_list = [
  'shift',
  'push',
  '',
  'length',
  'charCodeAt',
  'reverse',
  '424erSbWD',
  '50VJNKtb',
  '2285525hAxmKB',
  '2681065VjgJlj',
  'Zm1jZH92N2tkcFVhbXs6fHNjI2NgaA==',
  'split',
  '3IoFoig',
  '310080UgNxMY',
  '2282352jiOaqE',
  'fromCharCode',
  '3333978wBYWRq',
  'Not implemented.',
  'join',
  '236046XdgOCv',
  '6nMpKMt',
  '48517AjJpRI',
  'log',
];


(function (func, param2) {
  var func_cpy = func();

  while (true) {
    try {
      var number = 321734;

      if (number === param2) {
        break;
      } else {
        func_cpy['push'](func_cpy['shift']());
      }
    } catch (exception) {
      func_cpy['push'](func_cpy['shift']());
    }
  }
})(return_list_func, 321734);


function get_elem_operations_list(param1, param2) {
  return (
    (get_elem_operations_list = function (index, useless) {
      index = index - 265;
      return return_list_func()[index];
    }),
    get_elem_operations_list(param1, param2)
  );
}


var flag = "Zm1jZH92N2tkcFVhbXs6fHNjI2NgaA==";


function validateFlag(parameter) {
  var reversed_flag  = reverseFlag(parameter);
  var encrypted_flag = encryptFlag(reversed_flag);
  var decrypted_flag = decryptFlag(encrypted_flag);

  return decrypted_flag === getSolution();
}

/* I dunno how to reverse it but it's not that important */
function reverseFlag(parameter) {
  return parameter['split'](''), parameter['reverse'](), parameter['join']('');
}


function encryptFlag(parameter) {
  var string = '';

  for (var i = 0; i < parameter['length']; i ++) {
    var pos = parameter['charCodeAt'](i);
    var divider = pos ^ i;		// XOR

    string += String['fromCharCode'](divider);
  }
  
  return btoa(string);
}


function decryptFlag(parameter) {
  return "Not implemented.";
}


function getSolution() {
  return "Not implemented.";
}


function return_list_func() {
  var op_list = [
    operations_list[5],
    operations_list[6],
    operations_list[7],
    operations_list[8],
    operations_list[9],
    operations_list[10],
    operations_list[11],
    operations_list[12],
    operations_list[13],
    operations_list[14],
    operations_list[15],
    operations_list[16],
    operations_list[17],
    operations_list[18],
    operations_list[19],
    operations_list[20],
    operations_list[21],
  ];

  return (
    (return_list_func = function () {
      return op_list;
    }),
    return_list_func()
  );
}


console.log(flag);
