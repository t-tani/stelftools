# How to Install
stelftools はコマンドラインや IDA Pro / Ghidra のプラグインとして利用できます。

### init setup
stelftools が使用する python3 パッケージのインストールと、スクリプト内のパスの更新を行います。
```bash
./tools/setup/init.sh
```

## IDA Pro plugin setup
### Install stelftools IDA Plugin
IDA のプラグインディレクトリに stelftools へのシンボリックリンクを貼ります。
```bash
./tools/setup/ida.sh {path to IDA Pro install directory}
```

## Ghidra plugin setup
Ghidra のスクリプトディレクトリに stelftools へのシンボリックリンクを貼ります。
```bash
./tools/setup/ghidra.sh {path to ghidra install directory}
```

# How to Use
stelftools は 3 通りの方法で実行できます。

## Command line mode
`stelftools` は単一のエントリポイントで、4 つのサブコマンド (verb: `identify` / `symbolize` / `mkrule` / `fetch`) を持ちます。`stelftools --help` で一覧を、`stelftools <verb> --help` で個別フラグを確認できます。

*toolchain config JSON* (フラグ名や出力中では `cfg` と略記) は `signatures/<family>/<arch>/<name>.json` に置かれる設定ファイルで、対象ツールチェインの YARA ルール、エイリアスリスト (`.alist`)、依存関係リスト (`.dlist`) の所在をマッチング処理に伝えます。

#### 公開済みシグネチャの取得
シグネチャツリーはリポジトリには含まれていないため、GitHub Release の添付ファイルから取得します。
```bash
# マニフェストに記載されたすべてを取得
stelftools fetch

# 必要なアーキテクチャだけ取得
stelftools fetch --family bootlin-stable --arch mips32el,aarch64
```

#### ライブラリ関数とツールチェインの特定
```bash
stelftools identify /path/to/target
```
ELF のアーキテクチャと libc ファミリを自動検出し、候補となる config をすべて試して順位付けを行い、カバレッジ (一致率) に基づく判定 (`identified` / `unidentified`) を出力します。

- `--cfg PATH` — 単一のツールチェイン config を明示指定します (自動選択をスキップ)。
- `--threshold P` — `identified` 判定の閾値です。デフォルト `0.9` では、バイナリ中のライブラリ関数の 90% 以上が一致した場合に identified と判定します。`--strict` (= `--threshold 1.0`) を指定すると全関数の一致を要求します。
- `--coverage-metric {function,bytes}` — `function` (デフォルト。特定できた libc 関数数を、バイナリ中の libc 関数数で割った値) または `bytes` (マッチした libc 領域バイト数を libc 領域全体のバイト数で割った値。`function` 方式より前からある計算方法で、後方互換のため残しています)。
- `-o {default,compare,ida,ghidra,count,no}` — 関数ごとの出力形式。

##### どのツールチェインを試すべきか分からない場合の推奨順序
IoT マルウェアはごく少数のツールチェインに集中しているため、`stelftools identify` はその観測順で候補を試します。

- firmware linux 0.9.6 (`fl-0.9.6_{arch}`)
- firmware linux 0.9.7 〜 0.9.11 (`fl-{version}_{arch}`)
- aboriginal linux 1.0.0 〜 1.4.5 (`al-{version}_{arch}`)
- bootlin (`bl-stable-{version}_{libc}_{arch}`)
- その他

#### マッチングに使用する YARA ルール等の生成
```bash
stelftools mkrule /path/to/toolchain \
    --name {toolchain name} \
    --arch {target architecture} \
    --compiler /path/to/cross-gcc
```
- `<toolchain-path>` (位置引数、省略可) — `.a` / `.o` アーカイブを含むツールチェインのルートディレクトリ。省略した場合は `--compiler` から 2 階層上のディレクトリが自動で使われます。
- `--name` — シグネチャ名。先頭は既知の family prefix (`fl-`, `al-`, `bl-stable-`, `br-`, `ct-ng`, `ucli-pub-`, `synopsys_arc_gnu`) のいずれかである必要があります。
- `--arch` — ターゲットのアーキテクチャ。
- `--compiler` — ツールチェイン内の cross-gcc バイナリのパス。

#### ELF のシンボル化
```bash
stelftools symbolize /path/to/target --out-elf /path/to/output
```
`--cfg` を省略した場合は内部で identify を実行して最も一致率の高いツールチェインを選び、ELF のコピーに `.symtab` セクションを書き加えます。IDA / Ghidra は読み込み時にこの `.symtab` を参照するため、IDB / Ghidra プロジェクトを書き換えずに関数名が表示されます。

#### 旧 console-script との互換性
1.0 以前のハイフン区切りスクリプト (`stelftools-ident` / `stelftools-mkrule` / `stelftools-bruteforce` / `stelftools-symbolize` / `stelftools-fetch-signatures`) は引き続き動作しますが、非推奨警告 (deprecation warning) を出力したうえで新しいサブコマンドへ転送されます。新規に書く場合は `stelftools <verb>` を使ってください。


## IDA plugin mode
##### Library Function Identification
1. **File** → **Load file** → **Stelftools toolchain config file...**
2. ツールチェインのコンフィグファイルを選択します。
<img src="images/ida_func_ident.gif" width="90%">

関数名が更新されます。

##### YARA Rules Generation
1. **File** → **Produce file** → **Stelftools toolchain config file...**
2. ツールチェイン名を入力します。
3. ツールチェインのコンパイラを選択します。
4. ツールチェインのアーキテクチャを入力します。
<img src="images/ida_gen_rule.gif" width="90%">

ライブラリ関数の特定に使用する YARA ルール一式が生成されます。


## Ghidra plugin mode
##### Library Function Identification
0. **Script Manager** → Scripts/stelftools/python/**ghidra_stelftools.py** → **func_ident** を選択します。
1. ツールチェインの JSON コンフィグファイル (`toolchain_name.json`) を選択します。
<img src="images/ghidra_func_ident.gif" width="90%">

##### YARA Rules Generation
0. **Script Manager** → Scripts/stelftools/python/**ghidra_stelftools.py** → **make_rules** を選択します。
1. ツールチェイン名を入力します。
2. ツールチェインのディレクトリを選択します。
3. ツールチェインのコンパイラを選択します (任意項目)。
4. ツールチェインのアーキテクチャを入力します。
<img src="images/ghidra_makes.gif" width="90%">

stelftools の元になった論文と、その各節とコードの対応は [プロジェクト README](../README.md#references) および [docs/paper_to_code.md](paper_to_code.md) に記載しています。
