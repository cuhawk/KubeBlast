data "aws_iam_policy_document" "read" {
  statement {
    actions   = ["secretsmanager:GetSecretValue"]
    resources = ["*"]
  }
}

resource "aws_iam_user" "review" {
  name = "fixture"
}

resource "aws_iam_user_policy" "review" {
  user   = aws_iam_user.review.name
  policy = data.aws_iam_policy_document.read.json
}
