\NeedsTeXFormat{LaTeX2e}[2020/02/02]
\ProvidesClass{tjuthesis-Bachelor}

% 类选项处理
\newif\if@songnumber
\@songnumberfalse
\DeclareOption{songnumber}{\@songnumbertrue}
\ProcessOptions\relax

\LoadClass[a4paper,12pt,openany,oneside]{ctexbook}
\RequirePackage{geometry}
\RequirePackage{fancyhdr}
\RequirePackage{titletoc}
\RequirePackage{graphicx}
\RequirePackage{pdfpages}
\RequirePackage{pifont}
\RequirePackage{booktabs}
\RequirePackage{amsmath}
\RequirePackage{amsfonts}
\RequirePackage[hidelinks]{hyperref}
\RequirePackage{newtxmath}
\RequirePackage{caption}
\RequirePackage{xcolor}
\RequirePackage{listings}
\RequirePackage[style=gb7714-2015]{biblatex}
\RequirePackage{setspace}
\RequirePackage{indentfirst}
\RequirePackage{enumitem}
\RequirePackage{array}

\geometry{
    a4paper,
    left=35.7mm,
    right=27.7mm,
    top=27.5mm,
    bottom=25.4mm,
    headheight=14.5pt,
    headsep=21pt,
    footskip=22.4pt
}

%========================================
% 字体设置
%========================================
% 正文英文字体：Times New Roman
\setmainfont{Times New Roman}
\setsansfont{Times New Roman}
\setmonofont{Courier New}

% 中文字体设置
% 宋体：用于正文中文
\setCJKfamilyfont{song}[AutoFakeBold={2},Script=CJK]{SimSun}
\newcommand{\songtibf}{\CJKfamily{song}\bfseries}

% 黑体：用于标题
\setCJKfamilyfont{hei}[AutoFakeBold={2}]{SimHei}
\newcommand{\heitibf}{\CJKfamily{hei}\bfseries}

% 设置默认中文字体为宋体（启用伪粗体以支持加粗）
\setCJKmainfont[AutoFakeBold={2},Script=CJK]{SimSun}

%========================================
% 正文格式：行距固定值20磅，段落前后间距为0，首行缩进2字符
%========================================
% 小四号字约12pt，固定行距20磅（≈20bp），设定容错行距以缓解Overfull hbox
\linespread{1.0}\selectfont
\setlength{\parindent}{2em}
\setlength{\parskip}{0bp}
\setlength{\emergencystretch}{1.5em}
\tolerance=500
\AtBeginDocument{\setlength{\baselineskip}{20bp}}
\renewcommand{\footnotesize}{\zihao{5}}

% 设置列表环境行间距与正文一致
\setlist{nosep}
\setlist[itemize]{itemsep=0pt,parsep=0pt,topsep=0pt,partopsep=0pt}
\setlist[enumerate]{itemsep=0pt,parsep=0pt,topsep=0pt,partopsep=0pt}
\setlist[description]{itemsep=0pt,parsep=0pt,topsep=0pt,partopsep=0pt}

% 设置表格行间距与正文一致
\renewcommand{\arraystretch}{1.0}

%========================================
% 页眉页脚格式
%========================================
% 正文页面样式：有页眉和页码
\fancypagestyle{plain}{
    \fancyhf{}
    \fancyhead[C]{\CJKfamily{song}\zihao{5}\@cheading}
    \fancyfoot[C]{\CJKfamily{song}\zihao{-5}\thepage}
    \renewcommand{\headrulewidth}{0.5bp}
    \renewcommand{\footrulewidth}{0bp}
}
\fancypagestyle{noheader}{
    \fancyhf{}
    \fancyfoot[C]{\CJKfamily{song}\zihao{-5}\thepage}
    \renewcommand{\headrulewidth}{0bp}
    \renewcommand{\footrulewidth}{0bp}
}
% 空白页面样式：用于封面等
\fancypagestyle{empty}{
    \fancyhf{}
    \renewcommand{\headrulewidth}{0bp}
    \renewcommand{\footrulewidth}{0bp}
}
% 设置默认页面样式为plain
\pagestyle{plain}
\ctexset{chapter/pagestyle=plain}

% 前言部分（摘要、目录）使用大写罗马数字页码
\let\oldfrontmatter\frontmatter
\renewcommand{\frontmatter}{%
    \oldfrontmatter
    \renewcommand{\thepage}{\@Roman\c@page}%
}

%========================================
% 章节标题格式
%========================================
\setcounter{secnumdepth}{3}
\ctexset{
    contentsname={\mbox{目\quad 录}},
    chapter={
        format={\centering\CJKfamily{hei}\zihao{-3}},
        numberformat={\CJKfamily{hei}\zihao{-3}},
        number={\chinese{chapter}},
        name={第,章},
        aftername=\quad,
        beforeskip=30bp,
        afterskip=30bp,
    },
    section={
        format={\CJKfamily{hei}\zihao{4}},
        numberformat={\CJKfamily{hei}\zihao{4}},
        beforeskip=20bp,
        afterskip=20bp,
        aftername=\quad,
    },
    subsection={
        format={\CJKfamily{hei}\zihao{4}},
        numberformat={\CJKfamily{hei}\zihao{4}},
        beforeskip=13bp,
        afterskip=13bp,
        aftername=\quad,
    },
    subsubsection={
        format={\CJKfamily{hei}\zihao{4}},
        numberformat={\CJKfamily{hei}\zihao{4}},
        beforeskip=13bp,
        afterskip=13bp,
        aftername=\quad,
    }
}

%========================================
% 目录格式：各级标题逐级缩进2字符，页码前导符采用"..."
%========================================
\addtocontents{toc}{\protect\pagestyle{noheader}\protect\thispagestyle{noheader}}
\setcounter{tocdepth}{3}
\titlecontents{chapter}[0em]{\zihao{4}}{\thecontentslabel\quad}{}{\hspace{.5em}\titlerule*[5bp]{.}\zihao{4}\contentspage}
\titlecontents{section}[2em]{\zihao{4}}{\thecontentslabel\quad}{}{\hspace{.5em}\titlerule*[5bp]{.}\zihao{4}\contentspage}
\titlecontents{subsection}[4em]{\zihao{4}}{\thecontentslabel\quad}{}{\hspace{.5em}\titlerule*[5bp]{.}\zihao{4}\contentspage}

%========================================
% 图表标题格式：图序、表序与图题、表题之间空一个全角空格
% 图、表内容为五号字，中文字体为宋体，英文字体为Times New Roman
%========================================
\DeclareCaptionLabelSeparator{quadspace}{\quad}
\DeclareCaptionFont{wuhao}{\zihao{5}}
\captionsetup{font=wuhao,labelsep=quadspace}

% 图、表与其前后的正文之间要有一行的间距（约20磅）
\setlength{\intextsep}{20bp}
\setlength{\textfloatsep}{20bp}

% 图表公式编号格式：采用阿拉伯数字分章编号（如：图2-5，表3-2）
\renewcommand{\tablename}{表}
\renewcommand{\figurename}{图}
\renewcommand{\thefigure}{\thechapter-\arabic{figure}}
\renewcommand{\thetable}{\thechapter-\arabic{table}}
\renewcommand{\theequation}{\thechapter-\arabic{equation}}

% 图片插入宏
\newcommand{\figuremacro}[5]{
  \begin{figure}[#1]
    \centering
    \includegraphics[width=#4\textwidth]{#2}
    \caption{#3}
    \label{#5}
  \end{figure}
}

% 表格插入宏
\newcommand{\tablemacro}[5]{
    \begin{table}[#1]
    \centering
    \caption{#2}
    \begin{tabular}{ccc}
        \toprule
        #3
        \midrule
        #4
        \bottomrule
    \end{tabular}
    \label{#5}
\end{table}
}

\addbibresource{reference.bib}

%========================================
% 代码高亮样式
%========================================
\lstset{
    basicstyle=\ttfamily\small,
    numbers=left,
    numberstyle=\tiny,
    stepnumber=1,
    numbersep=8pt,
    frame=single,
    framerule=0.5pt,
    breaklines=true,
    breakatwhitespace=false,
    tabsize=4,
    showstringspaces=false,
    showspaces=false,
    showtabs=false,
    columns=flexible,
    keepspaces=true,
    keywordstyle=\color{blue},
    commentstyle=\color{green!50!black},
    stringstyle=\color{red!60!black},
    backgroundcolor=\color{gray!5},
    captionpos=b
}

%========================================
% 封面信息命令
%========================================
\newlength{\@info@width}
\setlength{\@info@width}{8cm}
\newcommand{\infowidth}[1]{\setlength{\@info@width}{#1}}
\newcommand{\ctitle}[1]{\gdef\@ctitle{#1}}\def\@ctitle{}
\newcommand{\caffil}[1]{\gdef\@caffil{#1}}\def\@caffil{}
\newcommand{\csubject}[1]{\gdef\@csubject{#1}}\def\@csubject{}
\newcommand{\cgrade}[1]{\gdef\@cgrade{#1}}\def\@cgrade{}
\newcommand{\cauthor}[1]{\gdef\@cauthor{#1}}\def\@cauthor{}
\newcommand{\cnumber}[1]{\gdef\@cnumber{#1}}\def\@cnumber{}
\newcommand{\csupervisor}[1]{\gdef\@csupervisor{#1}}\def\@csupervisor{}
\newcommand{\cheading}[1]{\gdef\@cheading{#1}}\def\@cheading{}
\newcommand{\cabstractcn}[1]{\gdef\@cabstractcn{#1}}\def\@cabstractcn{}
\newcommand{\cabstracten}[1]{\gdef\@cabstracten{#1}}\def\@cabstracten{}
\newcommand{\ckeywordcn}[1]{\gdef\@ckeywordcn{#1}}\def\@ckeywordcn{}
\newcommand{\ckeyworden}[1]{\gdef\@ckeyworden{#1}}\def\@ckeyworden{}

%========================================
% 生成封面页
%========================================
\newcommand{\makecover}{
    \begin{titlepage}
        \thispagestyle{empty}
        \begin{center}
        \includegraphics[width=0.4\textwidth]{figures/tjuname.eps}\\[21pt]
        {\zihao{2}\heitibf{本科生毕业论文}}
        \vfill
        \includegraphics[width=0.4\textwidth]{figures/tjulogo.eps}\\[20pt]
        {\zihao{3}\heitibf{题目：\@ctitle}}\\[30pt]
        \renewcommand{\arraystretch}{1.5}
        {\zihao{3}\songtibf{
            \begin{tabular}{lc}
                学\qquad 院 &  \underline{\makebox[\@info@width][c]{\@caffil}} \\[8pt]
                专\qquad 业 &  \underline{\makebox[\@info@width][c]{\@csubject}} \\[8pt]
                年\qquad 级 &  \underline{\makebox[\@info@width][c]{\@cgrade}} \\[8pt]
                姓\qquad 名 &  \underline{\makebox[\@info@width][c]{\@cauthor}} \\[8pt]
                学\qquad 号 &  \underline{\makebox[\@info@width][c]{\@cnumber}} \\[8pt]
                指导教师 &  \underline{\makebox[\@info@width][c]{\@csupervisor}} \\
            \end{tabular}
            }
        }
        \vspace{1cm}
        \end{center}
    \end{titlepage}
}

%========================================
% 生成摘要页
% 中文摘要："摘  要"宋体二号加粗居中，关键词宋体四号加粗
% 英文摘要："ABSTRACT" Times New Roman 二号加粗居中，KEY WORDS 四号加粗
%========================================
\newcommand{\makeabstract}{
    \chapter*{\CJKfamily{song}\zihao{2}\textbf{摘\quad 要}}
    \thispagestyle{noheader}
    \@cabstractcn
    \par\bigskip
    \noindent {\CJKfamily{song}\zihao{4}\textbf{关键词：}}
    \@ckeywordcn
    \chapter*{\rmfamily\zihao{2}\textbf{ABSTRACT}}
    \thispagestyle{noheader}
    \@cabstracten
    \par\bigskip
    \noindent {\rmfamily\zihao{4}\textbf{KEY WORDS:} }
    \@ckeyworden
}
