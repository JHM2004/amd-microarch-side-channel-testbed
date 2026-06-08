# 天津大学本科毕业论文

## 论文信息

- **题目**: 处理器微架构侧信道漏洞安全测试技术研究
- **作者**: 杨宇鑫
- **学号**: 3022207128
- **专业**: 软件工程
- **年级**: 2022级
- **导师**: 鲁赵骏
- **学院**: 智能与计算学部

## 编译方法

### 方法1: 使用编译脚本 (推荐)

```bash
cd /home/jhm/aes-flush-reload/thesis
./build.sh
```

### 方法2: 手动编译

```bash
cd /home/jhm/aes-flush-reload/thesis
xelatex tjumian.tex
biber tjumian
xelatex tjumian.tex
xelatex tjumian.tex
```

## 系统要求

- **操作系统**: Windows (推荐) / Linux / macOS
- **TeX发行版**: TeX Live 2023 或更高版本
- **编译引擎**: XeLaTeX
- **参考文献工具**: Biber

## 安装 TeX Live

### Windows
1. 下载 TeX Live: https://tug.org/texlive/
2. 运行安装程序，选择"完整安装"
3. 安装完成后，将 TeX Live 的 bin 目录添加到系统 PATH

### Ubuntu/Debian
```bash
sudo apt-get update
sudo apt-get install -y texlive-xetex texlive-lang-chinese \
    texlive-fonts-recommended texlive-latex-extra biber
```

### macOS
```bash
brew install --cask mactex
```

## 论文结构

```
thesis/
├── tjumian.tex              # 主文件
├── tjuthesis-Bachelor.cls   # 天津大学论文模板类
├── 独创性声明.pdf           # 原创性声明
├── reference.bib            # 参考文献
├── build.sh                 # 编译脚本
├── contents/
│   ├── introduction.tex     # 封面和摘要
│   ├── chapter1.tex         # 第一章：绪论
│   ├── chapter2.tex         # 第二章：相关技术背景
│   ├── chapter3.tex         # 第三章：攻击方法设计与实现
│   ├── chapter4.tex         # 第四章：实验与分析
│   ├── chapter5.tex         # 第五章：总结与展望
│   ├── appendix.tex         # 附录
│   └── acknowledgements.tex # 致谢
└── figures/
    ├── tjulogo.eps          # 校徽
    └── tjuname.eps          # 校名
```

## 注意事项

1. 编译前请确保已安装 TeX Live 并正确配置环境变量
2. 首次编译可能需要较长时间，因为需要生成字体缓存
3. 如果编译失败，请检查是否安装了所有必需的宏包
4. 论文使用了天津大学官方模板，请遵守学校的论文撰写规范

## 常见问题

### Q: 编译时出现 "xelatex: command not found" 错误
A: 请安装 TeX Live 并确保 xelatex 在系统 PATH 中。

### Q: 编译时出现字体错误
A: 请确保安装了中文字体（如 SimSun、SimHei 等）。

### Q: 参考文献不显示
A: 请确保运行了 `biber tjumian` 命令。

## 联系方式

如有问题，请联系导师或查阅天津大学本科生毕业论文撰写规范。
