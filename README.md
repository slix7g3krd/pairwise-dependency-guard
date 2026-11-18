# pairwise-dependency-guard

内部包名开始出现在公共源后，依赖混淆就有了入口：私有包只写名字不写 registry，构建时优先从公网拉取；scope 白名单只在前端校验，CI 仍用默认源；锁文件里的 resolved 指向公共源，没人复核；`company-utils` 这类内部前缀没有保留；版本用通配符，攻击者能发更高版本覆盖；hash 缺失或只校验 sha1；git 和本地路径依赖绕过 registry；依赖名大小写和下划线归一后撞名；传递依赖不检查来源；空依赖名被当成合法。security/dependency_guard.py 是核心，tests/test_dependency_guard.py 15个红。要修的是：内部包强制私有源；scope 白名单；锁文件来源校验；内部前缀保留；版本精确；hash 强校验；禁 git/本地路径；名称归一；传递依赖检查；空名拒绝。

## 运行

```bash
python -m pytest tests -q
```

初始状态：15 个用例失败。修复实现使全部用例通过，不要修改 `tests/` 下的测试。

子方向：其他；任务类型：Bugfix；语言/框架：Python 3, pytest；环境可复现等级：无外部依赖。
