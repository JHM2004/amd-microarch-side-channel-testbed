#!/bin/bash
cd /home/jhm/aes-flush-reload/thesis

# 优化编译选项：
# -interaction=nonstopmode: 遇到错误不停止
# -synctex=0: 不生成synctex文件（加速）
# -halt-on-error: 遇到严重错误时停止

echo "第一次编译..."
xelatex -interaction=nonstopmode -synctex=0 tjumian.tex

echo "处理参考文献..."
biber tjumian

echo "第二次编译..."
xelatex -interaction=nonstopmode -synctex=0 tjumian.tex

echo "第三次编译..."
xelatex -interaction=nonstopmode -synctex=0 tjumian.tex

echo "编译完成！"


# cd /home/jhm/aes-flush-reload/thesis && rm -f *.aux *.log *.out *.toc *.bbl *.blg *.bcf *.run.xml tjumian.pdf contents/*.aux && bash build.sh 2>&1 | tail -30