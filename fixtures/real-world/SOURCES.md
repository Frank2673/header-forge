# 真实世界语料来源

本目录下的 `*. _headers` 文件**全部来自公开仓库**，用途只有一个：
让 `tests/real-world.test.mjs` 在**不是我造的样本**上验证反向导入器。

## 为什么要有这个目录

自己构造的样本只会覆盖自己想到的情况。抓了 9 份真实配置后立刻发现了一件设计时
没想到的事：**`Cache-Control` 在真实配置里几乎总是按路径分别取值**（9 份里有 4 份，
最多一份有 14 个路径块）——这直接推翻了"全量导入"的默认行为，
详见 `src/importer.mjs` 里 `SECURITY_HEADERS` 的注释。

> 换言之：这个目录的存在价值不是"多几个测试"，而是**它抓到过一个真问题**。

## 来源清单

| 本地文件名 | 原始仓库 | 原始路径 |
| --- | --- | --- |
| `rustacean-station.org._headers` | [rustacean-station/rustacean-station.org](https://github.com/rustacean-station/rustacean-station.org) | `_headers` |
| `MailTape-v1._headers` | [MailTape/MailTape-v1](https://github.com/MailTape/MailTape-v1) | `_headers` |
| `openshift-knative-docs._headers` | [openshift-knative/docs](https://github.com/openshift-knative/docs) | `_headers` |
| `cossui-svelte._headers` | [cossui-svelte/cossui-svelte](https://github.com/cossui-svelte/cossui-svelte) | `_headers` |
| `keyper._headers` | [pinkpixel-dev/keyper](https://github.com/pinkpixel-dev/keyper) | `_headers` |
| `veil._headers` | [simoneamico-ux-dev/veil](https://github.com/simoneamico-ux-dev/veil) | `_headers` |
| `Markdown-Viewer._headers` | [ThisIs-Developer/Markdown-Viewer](https://github.com/ThisIs-Developer/Markdown-Viewer) | `_headers` |
| `DevOpsSecurityChecklist._headers` | [sqreen/DevOpsSecurityChecklist](https://github.com/sqreen/DevOpsSecurityChecklist) | `_headers` |
| `run-elixir._headers` | [PJUllrich/run-elixir](https://github.com/PJUllrich/run-elixir) | `_headers` |

获取方式：`gh api -H "Accept: application/vnd.github.raw" repos/<owner>/<repo>/contents/_headers`

## 版权与使用说明

这些文件是**功能性配置文件**（响应头清单），不含创造性表达；此处以原样保存，
仅用于解析器的互操作性测试，不参与本项目的构建产物。
每个文件仍归其原始项目所有，并受该项目自身许可证约束 —— 需要复用时请回到上表链接查看。

## 重新抓取

```bash
gh api -H "Accept: application/vnd.github.raw" \
  repos/rustacean-station/rustacean-station.org/contents/_headers \
  > fixtures/real-world/rustacean-station.org._headers
```

如果某个仓库改名或转为私有，抓取会返回 404 —— 那时请从上表移除该条目，
或换一个新的公开仓库。语料的价值在于"真实"，不在于"固定"。
