# Goferret 复现与验证 workflow-v2

把检测器的 `report.json` 变成给上游维护者的复现报告。六步，一个 CLI：

```
select → evidence → design → run → judge → report
 机械     机械      LLM×1    Docker   规则     渲染
```

- **只有 `design` 调用 LLM**（temperature 0，按输入哈希缓存）。测试编译通过即冻结为 `experiment_test.go`，之后 `run` 只重放，不再生成。
- **判定只看标记**：测试每臂打印 `REACHED / RESULT / OBSERVED` 三行，`judge.py` 按规则给出 `已复现 / 不成立 / 未能复现`。
- **环境固定**：一次性容器、`--network none`、模块缓存只读、镜像 digest 写入 `run.log`。
- **报告只写已复现的问题**：位置、一句话问题、一键复现脚本、预期输出、修复建议；其余在附录一行一条。

## 安装与配置

需要 Python 3.9+、Git、Go、Docker 和 `rsync`。工作流 Python 脚本使用标准库；检测器的安装见 [detector/README.md](../detector/README.md)。

在仓库根目录执行：

```sh
cd workflow-v2
cp config.example.json config.json
```

编辑 `config.json`：文件系统路径填写本机绝对路径，`goferret_dir` 指向 `detector/`，LLM 配置读取其中的 `.env`。源码放在 `<src_root>/owner__repository/`，报告放在 `<reports_root>/owner__repository/<report_file>`；二者必须对应相同源码版本。`repos` 填写 `owner/repository` 列表。

提前拉取 Docker 镜像并准备 Linux 容器需要的 Go 模块缓存；运行时网络关闭且 `GOPROXY=off`，缺依赖会导致构建失败。跨机器重复实验时可配置实际的 `golang@sha256:...`；代码记录镜像 digest，但不会自动把标签固定为 digest。

## 执行

```sh
python3 repro.py all --repos ffuf/ffuf
python3 repro.py check-stable --repos ffuf/ffuf     # 再跑一遍，差异应为 0
```

设计取舍、判定规则和首批结果见 [设计说明.md](设计说明.md)。

示例中的仓库需先准备对应输入。`python3 repro.py --help` 查看参数；`REPRO_CONFIG=/absolute/path/to/config.json` 可切换配置。`design` 会产生 LLM 费用并运行生成的测试，请在隔离的实验环境中使用。

本仓库不附带本地案例、LLM 缓存、扫描结果和目标源码。设计说明中的历史统计未在此次上传中重新验证；`validate_summary.py` 需要另行准备 `cases_validation/advisories.json` 及相应扫描、案例数据。设计说明引用的 `cases_validation/README.md` 属于未发布的本地实验记录。

产物在 `cases/<slug>/`：`selected.json`、`<unit>/evidence.txt|json`、`experiment_test.go`、`test.sha256`、`spec.json`、`run.log`、`verdict.json`、`repro.sh`、`report_<slug>.md`；跨仓库汇总在 `cases/summary.csv`。
