# Iran Sans Font Files

Please add the following Iran Sans font files to this directory:

- IRANSansWeb.eot
- IRANSansWeb.woff2
- IRANSansWeb.woff
- IRANSansWeb.ttf
- IRANSansWeb_Bold.eot
- IRANSansWeb_Bold.woff2
- IRANSansWeb_Bold.woff
- IRANSansWeb_Bold.ttf

You can download Iran Sans from:
- Official website: https://fontiran.com/fonts/iransans/
- GitHub: https://github.com/rastikerdar/iran-sans

Or use CDN links by changing the CSS to:
```css
@font-face {
    font-family: 'Iran Sans';
    src: url('https://cdn.jsdelivr.net/gh/rastikerdar/iran-sans@5/fonts/eot/IRANSansWeb.eot');
    src: url('https://cdn.jsdelivr.net/gh/rastikerdar/iran-sans@5/fonts/eot/IRANSansWeb.eot?#iefix') format('embedded-opentype'),
         url('https://cdn.jsdelivr.net/gh/rastikerdar/iran-sans@5/fonts/woff2/IRANSansWeb.woff2') format('woff2'),
         url('https://cdn.jsdelivr.net/gh/rastikerdar/iran-sans@5/fonts/woff/IRANSansWeb.woff') format('woff'),
         url('https://cdn.jsdelivr.net/gh/rastikerdar/iran-sans@5/fonts/ttf/IRANSansWeb.ttf') format('truetype');
    font-weight: normal;
    font-style: normal;
}
```