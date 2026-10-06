"""在一次性、断网的容器里跑一份冻结测试。

每次：复制 T 版本源码到临时目录 → 写入测试文件 → docker run --rm --network none → 收原始输出。
模块缓存只读挂载，GOPROXY=off；构建缓存用命名卷（只影响速度，不影响结果）。
"""
import os, re, shutil, subprocess, tempfile, uuid

ENV = {'GOPROXY': 'off', 'GOFLAGS': '-mod=mod', 'GOWORK': 'off', 'GOTOOLCHAIN': 'local', 'TZ': 'UTC'}
HERE = os.path.dirname(os.path.abspath(__file__))


def image_digest(image):
    p = subprocess.run(['docker', 'image', 'inspect', image, '--format', '{{index .RepoDigests 0}}'],
                       capture_output=True, text=True)
    return p.stdout.strip() or image


def run_test(cfg, src_dir, mod_rel, pkg_rel, test_filename, test_code, run_pattern, timeout):
    """mod_rel：go.mod 所在目录相对仓库根；pkg_rel：包目录相对 go.mod 目录。
    返回 dict(cmd, rc, output, timed_out, build_failed, image)。"""
    os.makedirs(os.path.join(HERE, 'tmp'), exist_ok=True)
    tmp = tempfile.mkdtemp(prefix='repro_', dir=os.path.join(HERE, 'tmp'))
    try:
        work = os.path.join(tmp, 'src')
        subprocess.run(['rsync', '-a', '--exclude', '.git', src_dir + '/', work + '/'], check=True)
        if test_code is not None:  # None = 只检查包本身能否编译
            with open(os.path.join(work, mod_rel, pkg_rel, test_filename), 'w', encoding='utf-8') as f:
                f.write(test_code)
        name = 'repro_' + uuid.uuid4().hex[:10]
        wd = '/src' if mod_rel in ('', '.') else '/src/' + mod_rel
        cmd = ['docker', 'run', '--rm', '--network', 'none', '--name', name,
               '-v', f'{work}:/src', '-v', f"{cfg['modcache']}:/go/pkg/mod:ro",
               '-v', f"{cfg['gocache_volume']}:/root/.cache/go-build", '-w', wd]
        for k, v in ENV.items():
            cmd += ['-e', f'{k}={v}']
        pkg = '.' if pkg_rel in ('', '.') else './' + pkg_rel
        cmd += [cfg['docker_image'], 'go', 'test', pkg, '-run', run_pattern, '-count=1', '-v']
        timed_out = False
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            rc, out = p.returncode, p.stdout + p.stderr
        except subprocess.TimeoutExpired as e:
            subprocess.run(['docker', 'kill', name], capture_output=True)
            timed_out = True
            so = e.stdout or b''
            rc, out = -9, (so.decode(errors='replace') if isinstance(so, bytes) else so) + '\n[timeout]'
        # 编译失败的判据：go test 明确报 build/setup failed，或进程非 0 退出且没有跑到任何测试（如 go.mod 版本要求不满足、包无法加载）
        ran_tests = re.search(r'^(=== RUN|--- (PASS|FAIL)|ok\s|PASS|FAIL\s)', out, re.M) is not None
        build_failed = ('[build failed]' in out or '[setup failed]' in out or 'cannot find package' in out
                        or (rc != 0 and not timed_out and not ran_tests))
        return dict(cmd=' '.join(cmd).replace(work, '<src>'), rc=rc, output=out, timed_out=timed_out,
                    build_failed=build_failed, image=image_digest(cfg['docker_image']))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
