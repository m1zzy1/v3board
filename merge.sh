#!/bin/bash
set -e

COMMON_REMOTE=v2board
COMMON_URL=https://github.com/wyx2685/v2board.git
COMMON_BRANCH=master
PRIVATE_BRANCH=master

echo "🚀 确认远端是否存在..."
if ! git remote | grep -q "^$COMMON_REMOTE$"; then
  echo "➕ 添加远程 $COMMON_REMOTE -> $COMMON_URL"
  git remote add $COMMON_REMOTE $COMMON_URL
else
  echo "✅ 已存在远端 $COMMON_REMOTE"
fi

echo "📥 拉取公共库最新代码..."
git fetch $COMMON_REMOTE $COMMON_BRANCH

echo "🔀 切换到私有分支 $PRIVATE_BRANCH"
git checkout $PRIVATE_BRANCH

echo "🔀 尝试合并 $COMMON_REMOTE/$COMMON_BRANCH ..."
set +e
git merge --allow-unrelated-histories --no-ff $COMMON_REMOTE/$COMMON_BRANCH -m "merge: sync from EZ-Theme/$COMMON_BRANCH"
MERGE_EXIT_CODE=$?
set -e

if [ $MERGE_EXIT_CODE -ne 0 ]; then
  echo "⚠️ 合并过程中出现冲突，请手动解决："
  echo "   👉 git status"
  echo "   👉 修改后执行 git add . && git commit"
else
  echo "✅ 合并完成并已提交"
fi
