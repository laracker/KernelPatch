# hidefeature

apatch内核模块用于隐藏mounts&mountinfo&mountstats&maps&smaps内的特征

用完frida之后完美校园老是打不开，要隐藏maps里的一些内容，于是写了这个模块 :)

ps: 测试下来和cherish peekaboo模块冲突，可以卸载掉它再用(修补进内核之后重启之后还会回来，卸载也没事)

# 用法
参考文章 https://www.52pojie.cn/thread-1977664-1-1.html 来配置环境，
然后下载 https://github.com/bmax121/KernelPatch ，放到 kpms 目录下，执行make编译出 
