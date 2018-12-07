/**
 * @Author: zero
 * @Date:   2017-10-18T16:05:14+08:00
 * @Last modified by:   zero
 * @Last modified time: 2017-10-20T14:31:47+08:00
 */
import xss from 'xss';

// const URL_REG = /(https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9]
//  [a-zA-Z0-9-]+[a-zA-Z0-9]\.[a-zA-Z]{2,}|www\.[a-zA-Z0-9][a-zA-Z0-9-]
//  +[a-zA-Z0-9]\.[a-zA-Z]{2,}|https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9]\.[a-zA-Z]{2,}
//  |www\.[a-zA-Z0-9]\.[a-zA-Z]{2,})/g; // eslint-disable-line

// URL: /https?:\/\/(([a-zA-Z0-9_-])+(\.)?)*(:\d+)?(\/((\.)?(\?)?=?&?[a-zA-Z0-9_-](\?)?)*)*/ig
// IP: /[0-9]{0,3}\.[0-9]{0,3}\.[0-9]{0,3}\.[0-9]{0,3}/ig
// 手机号: /\+?(0|86|17951)?(13[0-9]|15[012356789]|17[678]|18[0-9]|14[57])[0-9]{8}/ig

const REGS = {
  URL: /https?:\/\/(([a-zA-Z0-9_-])+(\.)?)*(:\d+)?(\/((\.)?(\?)?=?&?[a-zA-Z0-9_-](\?)?)*)*/ig,
  IP: /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ig,
  // TEL: /\+?(0|86|17951)?(13[0-9]|15[012356789]|17[678]|18[0-9]|14[57])[0-9]{8}/ig,
  TEL: /((\+?(86)?[- ]?1\d{2}[- ]?\d{4}[- ]?\d{4})|((400|800)[- ]?\d{3}[- ]?\d{4})|((0\d{2,3})?[- ]?\d{7,8})|(95\d{3}))/ig,
  EMAIL: /\w+([-+.]\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*/ig,
  SCHEMA: /[a-zA-Z]+:\/\/[0-9a-zA-Z.?=]+/,
};

const REPLACE_REGS = {
  URL: /\{URL[0-9]+\}/ig,
  IP: /\{IP[0-9]+\}/ig,
  TEL: /\{TEL[0-9]+\}/ig,
  EMAIL: /\{EMAIL[0-9]+\}/ig,
};

const textContainer = {
  URL: [],
  IP: [],
  TEL: [],
  EMAIL: [],
};

export function transformSpecialChars(str) {
  return str.toString()
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/\r?\n/g, '<br />');
}

//  Replace rules:
//  Before: 12345678909http://www.baidu.com 127.0.0.1email@email.com1234567
//  After: {TEL0}{URL0} {IP0}{EMAIL0}{TEL1}

export function replaceText(type, text) {
  textContainer[type].push(text);
  return `{${type}${textContainer[type].length - 1}}`;
}

export function transformText2Replacement(text, options = {}) {
  const { proxy = '' } = options;
  return text
    .replace(
      REGS.URL,
      url => replaceText('URL', `<a rel="noopener noreferer" href="${proxy}${url.indexOf('http') !== -1 ? url : `http://${url}`}">${url}</a>`),
    ).replace(
      REGS.IP,
      url => replaceText('IP', `<a rel="noopener noreferer" href="${proxy}${url.indexOf('http') !== -1 ? url : `http://${url}`}">${url}</a>`),
    ).replace(
      REGS.TEL,
      tel => replaceText('TEL', `<a href="tel:${tel.replace(/[- ]/, '')}">${tel}</a>`),
    ).replace(
      REGS.EMAIL,
      email => replaceText('EMAIL', `<a href="mailto:${email}">${email}</a>`),
    );
    // .replace(
    //   REGS.SCHEMA,
    //   schema => replaceText('SCHEMA', `<a href="${schema}">电话中心</a>`),
    // );
}

export function transformReplacement2Url(text) {
  return text
    .replace(
      REPLACE_REGS.URL,
      () => textContainer.URL.shift(),
    ).replace(
      REPLACE_REGS.IP,
      () => textContainer.IP.shift(),
    ).replace(
      REPLACE_REGS.TEL,
      () => textContainer.TEL.shift(),
    ).replace(
      REPLACE_REGS.EMAIL,
      () => textContainer.EMAIL.shift(),
    );
}

export function filterUrl(text) {
  return xss(transformReplacement2Url(transformText2Replacement(text)));
}
