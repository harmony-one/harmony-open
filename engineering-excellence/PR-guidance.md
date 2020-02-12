# Harmony Engineering PR guidance

## Introduction

This document proposes the guidance on the pull request (PR) for our development projects.
The goals are to improve the quality of our code commits and to ease the communication cost of the engineering team.
A self-explanatory, self-contained PR will increase the development velocity and increase the team productivity.

## Tenets

The tenets of the guidance is the following, borrowed from Amazon LP.

- Insist on the highest standard
  - As a proud engineering team, we are consistently looking for high quality of the code review and commits.
This is also in line with our open source strategy to exemplify our engineering excellence to the community.
- Bias for action
  - We shall also move fast when needed. We believe in a fast iteration is the best way to improve our product.
- Ownership
  - Code view and PR should be owned by engineers and the owner will drive the consensus as leaders. All comments have to be addressed/agreed.

## Mandatory Requirement

- Each commit submitted to master branch and release branch has to have [sound commit message](https://chris.beams.io/posts/git-commit/) and logical scope.
- Run ./ **test/test\_before\_submit.sh** to ensure that the code conforms to basic standards and passes tests, and that the build is successful. You may need to install all the build tools in order to have a successful run.
- Run ./ **test/debug.sh** to ensure there is no regression on the basic consensus.
- Use [category] to classify the commit into a different category, such like
  - [consensus], [p2p], [resharding], [staking], [leader], [wallet], [misc], etc …
- If your commit is to fix a certain issue, please add the issue number/link to the commit message, such #575, [https://github.com/harmony-one/harmony/issues/767](https://github.com/harmony-one/harmony/issues/767), and so on.
- Add a [TEST] section in every PR describing your test process and results
  - Add the test logs to [https://gist.github.com/](https://gist.github.com/) and link in the PR

## Automation

- Travis-CI
  - Every PR in github.com will be built in Travis-CI
- Jenkins
  - Every PR in github.com will be sent to Jenkins job. [http://jenkins.harmony.one/job/build\_test\_on\_pr/](http://jenkins.harmony.one/job/build_test_on_pr/) The result will be notified in #team-dev-jenkins discord channel.
  - Use &quot; **Jenkins, test this please**&quot;, in the comment to re-trigger the Jenkins test.

## Best Practices

- Use a WIP branch to save your daily work
  - Back up your WIP branch in your own GitHub fork (not in the main harmony-one repo)
- Rebase every day to make sure your code integrates with the latest ToT (top of the tree)
  - git pull --rebase
  - [https://www.atlassian.com/git/tutorials/rewriting-history/git-rebase](https://www.atlassian.com/git/tutorials/rewriting-history/git-rebase)
- Use interactive rebase to squash, reorder, remove small commits, especially before submitting the initial PR.
  - git rebase -i \&lt;SHA1\&gt;
  - [https://git-scm.com/book/en/v2/Git-Tools-Rewriting-History](https://git-scm.com/book/en/v2/Git-Tools-Rewriting-History)
- Submit github Issues for every TODO or FIXME that you intended to put into the comments.  This will help us keep track of the issues better in GitHub.
