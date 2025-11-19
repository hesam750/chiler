# BYekan Font Files

Please add the following BYekan font files to this directory:

- BYekan.eot
- BYekan.woff2
- BYekan.woff
- BYekan.ttf
- BYekan-Bold.eot
- BYekan-Bold.woff2
- BYekan-Bold.woff
- BYekan-Bold.ttf

You can download BYekan from:
- Official website: https://fontiran.com/fonts/byekan/
- GitHub: https://github.com/rastikerdar/byekan

Or use CDN links by changing the CSS to:
```css
@font-face {
    font-family: 'BYekan';
    src: url('https://cdn.jsdelivr.net/gh/rastikerdar/byekan@1/fonts/eot/BYekan.eot');
    src: url('https://cdn.jsdelivr.net/gh/rastikerdar/byekan@1/fonts/eot/BYekan.eot?#iefix') format('embedded-opentype'),
         url('https://cdn.jsdelivr.net/gh/rastikerdar/byekan@1/fonts/woff2/BYekan.woff2') format('woff2'),
         url('https://cdn.jsdelivr.net/gh/rastikerdar/byekan@1/fonts/woff/BYekan.woff') format('woff'),
         url('https://cdn.jsdelivr.net/gh/rastikerdar/byekan@1/fonts/ttf/BYekan.ttf') format('truetype');
    font-weight: normal;
    font-style: normal;
}
```