module.exports = [
  { test: false
  , insecure: false
  , server: true
  , desc: "key for secure clients (ssl enabled web servers - node, ruby, python, etc)"
  , key: "ID__67785aa9722e826a21543d0c45ec"
  , secret: "SK__kIpxhcXC4hM1FMj8xATxejUYkMPu"
  }
, { test: false
  , insecure: true
  , server: false
  , desc: "key for insecure clients (browser, native apps, mobile apps)"
  , key: "ID__1a503bda47a3fe3a00543166333f"
  }
, { test: true
  , insecure: false
  , server: true
  , desc: "test key for secure clients (ssl enabled web servers - node, ruby, python, etc)"
  , key: "TEST_ID_4726583df676405851557a5d"
  , secret: "TEST_SK_GpohDU1P6C8WYRo0VKRRP1Cy"
  }
, { test: true
  , insecure: true
  , server: false
  , desc: "test key for insecure clients (browser, native apps, mobile apps)"
  , key: "TEST_ID_d7111005bf268904168d88ef"
  }
];
