[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

# **CloudGauge**

注: 本ツールはGoogleが公式にサポートする製品ではありません。このプロジェクトは [Google Open Source Software Vulnerability Rewards Program](https://bughunters.google.com/open-source-security)の対象外です。

CloudGaugeは、Google Cloudの組織（Organization）に対して、コンプライアンス、セキュリティ、コスト最適化、およびベストプラクティスの包括的なチェックを実行するように設計されたWebアプリケーションです。

Python/Flaskで構築され、Google Cloud Run上にサーバーレスアプリケーションとしてデプロイされます。このアプリケーションはCloud Tasksを活用してスキャンを非同期で実行するため、非常に大規模な組織であっても、ブラウザのタイムアウトを発生させることなくスキャン可能です。

最終的な結果は、Google Cloud Storageバケットに保存されるインタラクティブなHTMLレポートおよびCSVファイルとして表示されます。レポートには、Geminiを活用したエグゼクティブサマリーや、gcloudコマンドによる修正案の提案も機能に含まれています。

![CloudGauge Report Demo](./assets/cloudgauge.gif)

## **目次**
* [機能](#機能)
* [Architecture](#アーキテクチャ)
* [デプロイ手順](#デプロイ手順)
  * [共通の前提条件（すべての方法で必須）](#共通の前提条件すべての方法で必須)
  * [方法 1: ソースからデプロイ（推奨）](#方法-1-ソースからデプロイ推奨)
  * [方法 2: gcloudを使用した手動ビルド＆デプロイ](#方法-2-gcloudを使用した手動ビルドデプロイ)
* [使い方](#使い方)
* [トラブルシューティング](#トラブルシューティング)
* [クリーンアップスクリプト](#クリーンアップスクリプト)
* [ライセンスとサポート](#ライセンスとサポート)

## **機能**

CloudGaugeは、Google Cloud Architecture Frameworkを基に、Organization内のプロジェクトを以下の主要項目を対象にスキャンする仕様です。

### **Security & Identity**

* **組織ポリシー**: ベストプラクティスのリストと照合して、ブール型ポリシーをチェック。
* **組織IAM**: 組織レベルでのパブリックプリンシパル（`allUsers`, `allAuthenticatedUsers`）および基本ロール（`owner`, `orgAdmin`）をスキャン。
* **プロジェクトIAM**: すべてのプロジェクトをスキャンし、基本ロールの`roles/owner`と`roles/editor`が使用されていないかの確認。
* **Security Command Center**: SCC Premiumが有効になっていることを検証。
* **SAキーのローテーション**: 90日以上経過したユーザー管理のサービスアカウントキーを検出。
* **公開GCSバケット**: インターネットに公開されているGCSバケットを検出。
* **オープンなファイアウォールルール**: すべてのVPCをスキャンし、インターネットに開放されているファイアウォールルール（`0.0.0.0/0`）を検出。

### **Cost Optimization**

* **アイドル状態のリソース**: アイドル状態のCloud SQLインスタンス、VM、Persistent Disc、および関連付けられていないIPアドレスを検出。
* **ライトサイジング（適正化）**: 過剰に供与されたVMや、使用率の低いReservationsを特定。
* **コストインサイト**: CPU/メモリ使用率、アイドル状態のイメージなどを詳細にスキャン。

### **Reliability & Resilience**

* **必須連絡先**: `SECURITY`（セキュリティ）、`TECHNICAL`（技術）、`LEGAL`（法務）カテゴリの連絡先が設定されていることを確認。
* **サービスヘルス**: Personalized Service Health （PSH）APIが有効になっていることを検証。
* **Cloud SQLのレジリエンス**: 高可用性（HA）構成、自動バックアップ、ポイントインタイムリカバリ（PITR）をチェック。
* **GCSのバージョニング**: オブジェクトのバージョニングが有効になっていないバケットを検出。
* **GKEの衛生管理**: リリースチャンネルを使用していないクラスタや、自動アップグレードが無効になっているノードプールをチェック。
* **耐久性の検証**: ゾーンMIG（リージョンMIGを推奨）および単一リージョンのディスクスナップショットを特定。

### **Operational Excellence & Observability**

* **監査ログ**: 組織レベルのログシンク（Log Sink）を確認。
* **OS Configの適用状況**: OS Configサービスの対象外となっている実行中のVM（GKE/Dataprocを除く）を特定。
* **モニタリングの適用状況**: 重要なアラートポリシー（例: クォータ、Cloud SQL、GKEなど）が抜け落ちているプロジェクトをスキャン。
* **ネットワークアナライザ**: VPC、GKE、およびPSA（Private Service Access）のIPアドレス使用率に関するインサイトを取り込み、標準化。
* **スタンドアロンVM**: マネージドインスタンスグループ（MIG）によって管理されていないVMを検出。
* **クォータ使用率**: 使用率が80%を超えているリージョンのコンピューティングクォータを特定。
* **放置されたプロジェクト**: 使用率の低いプロジェクトを検出。

## **アーキテクチャ**

このアプリケーションは、綿密で、スケーラブルかつ非同期な「fire-and-forget」パターンを採用しています。これにより、即座に応答を受け取る一方で、負荷の高い作業（数分かかる場合があります）を**バックグラウンドで実行**することができます。

1. **UIトリガー**: ユーザーがCloud RunのURLにアクセスし、組織ID（Organization ID）を送信します。
2. **タスク作成**: `/scan`エンドポイントがスキャン詳細を含む**Cloud Task**を作成し、ユーザーをステータスページにリダイレクトします。
3. **バックグラウンドワーカー**: Cloud Tasksがバックグラウンドで`/run-scan`エンドポイントを安全に呼び出します。
4. **並列処理**: ワーカーはスレッドプールを使用してプロジェクトレベルのスキャンを並行して実行し、数十のチェック処理を行います。
5. **レポート保存**: ワーカーはHTML/CSVレポートを生成し、Google Cloud Storageにアップロードします。
6. **ステータスポーリング**: ユーザーのステータスページは、レポートファイルがGCSで見つかるまでAPIエンドポイントをポーリングし、見つかった時点でダウンロードリンクを表示します。

### **Architecture Diagram**

下図は非同期な "fire-and-forget" パターンを可視化したものになります。

```mermaid
graph LR
    %% The diagram is now Left-to-Right for a clearer flow.
    %% Custom styling has been removed to ensure readability on any background.

    %% Column 1: User
    subgraph User
        A[Selects Scan Scope] --> B{Lists Resources};
        B --> C[Selects Resource ID];
        C --> D[Submits Form];
    end

    %% Column 2: The "Frontend" part of the Cloud Run service
    subgraph Cloud Run - Initial Request
        D -- "1. POST Request" --> E{Scan Endpoint};
        E -- "2. Creates Task" --> F[(Cloud Tasks)];
        E -- "3. Redirects" --> G[Status Page];
        G -- "7. Polls API" --> H{Status API};
    end

    %% Column 3: The "Backend" part of the Cloud Run service (the worker)
    subgraph Cloud Run - Background Worker
        F -- "4. Invokes Worker" --> I{Worker Endpoint};
        subgraph Worker Process
            I --> J[1. Init status.json];
            J --> K{2. Start Parallel Checks};
            K -- "Dispatches" --> L1[IAM Checks];
            K -- "Dispatches" --> L2[Cost Checks];
            K -- "Dispatches" --> L3[...];
            L1 -- "Writes to" --> M([Local /tmp Files]);
            L2 -- "Writes to" --> M;
            L3 -- "Writes to" --> M;
            M --> N[3. Aggregate Findings];
            N --> O[4. Generate Reports];
            O --> P[5. Upload Reports];
            P --> Q[6. Cleanup tmp Files];
        end
    end

    %% Column 4: External Google Cloud Services
    subgraph External GCP Services
        L1 -- "queries" --> APIS([Cloud APIs]);
        L2 -- "queries" --> APIS;
        L3 -- "queries" --> APIS;
        
        H -- "reads" --> GCS_STATUS([status.json in GCS]);
        K -- "sends progress updates to" --> GCS_STATUS;
        
        P -- "writes to" --> GCS_REPORTS([Final Reports in GCS]);
    end
```

## **デプロイ手順** 

まず**共通の前提条件**に従い、その後に**方法 1** または **方法 2** のどちらかに従いデプロイしてください。

### **共通の前提条件（すべての方法で必須）** 

1. **APIの有効化**:
   * 課金が有効になっているGoogle Cloudプロジェクト。
   * [gcloud CLI](https://cloud.google.com/sdk/install) )がインストールされ、認証されていること（`gcloud auth login`）。
   * 以下のコマンドを実行して、必要なすべてのAPIを有効にします:

   ```
   gcloud services enable \
       run.googleapis.com \
       cloudbuild.googleapis.com \
       cloudtasks.googleapis.com \
       iam.googleapis.com \
       cloudresourcemanager.googleapis.com \
       logging.googleapis.com \
       recommender.googleapis.com \
       securitycenter.googleapis.com \
       servicehealth.googleapis.com \
       essentialcontacts.googleapis.com \
       compute.googleapis.com \
       container.googleapis.com \
       sqladmin.googleapis.com \
       osconfig.googleapis.com \
       monitoring.googleapis.com \
       storage.googleapis.com \
       aiplatform.googleapis.com \
       cloudasset.googleapis.com
   ```
   

2. **サービスアカウントの作成と権限の付与**:
* このサービスアカウント（SA）は、Cloud Runサービスが組織をスキャンし、タスクを作成するために使用されます。
```
   # Set your Organization ID
   export ORG_ID="<your-org-id>"

   

   # Set Project and SA variables

   export PROJECT_ID=$(gcloud config get-value project)
   export SA_NAME="cloudgauge-sa"
   export SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

   

   # Create the Service Account

   gcloud iam service-accounts create ${SA_NAME} --display-name="CloudGauge Service Account"

   

   #  Grant Permissions 

   

   # 1. Grant ORG-level roles to read assets and policies

   gcloud organizations add-iam-policy-binding ${ORG_ID} --member="serviceAccount:${SA_EMAIL}" --role="roles/browser"

   gcloud organizations add-iam-policy-binding ${ORG_ID} --member="serviceAccount:${SA_EMAIL}" --role="roles/cloudasset.viewer"

   gcloud organizations add-iam-policy-binding ${ORG_ID} --member="serviceAccount:${SA_EMAIL}" --role="roles/compute.networkViewer"

   gcloud organizations add-iam-policy-binding ${ORG_ID} --member="serviceAccount:${SA_EMAIL}" --role="roles/essentialcontacts.viewer"

   gcloud organizations add-iam-policy-binding ${ORG_ID} --member="serviceAccount:${SA_EMAIL}" --role="roles/recommender.iamViewer"

   gcloud organizations add-iam-policy-binding ${ORG_ID} --member="serviceAccount:${SA_EMAIL}" --role="roles/logging.viewer"

   gcloud organizations add-iam-policy-binding ${ORG_ID} --member="serviceAccount:${SA_EMAIL}" --role="roles/monitoring.viewer"

   gcloud organizations add-iam-policy-binding ${ORG_ID} --member="serviceAccount:${SA_EMAIL}" --role="roles/orgpolicy.policyViewer"

   gcloud organizations add-iam-policy-binding ${ORG_ID} --member="serviceAccount:${SA_EMAIL}" --role="roles/resourcemanager.organizationViewer"

   gcloud organizations add-iam-policy-binding ${ORG_ID} --member="serviceAccount:${SA_EMAIL}" --role="roles/servicehealth.viewer"

   gcloud organizations add-iam-policy-binding ${ORG_ID} --member="serviceAccount:${SA_EMAIL}" --role="roles/securitycenter.settingsViewer"

   gcloud organizations add-iam-policy-binding ${ORG_ID} --member="serviceAccount:${SA_EMAIL}" --role="roles/iam.securityReviewer"

   

   

   # 2. Grant PROJECT-level roles (on the project where Cloud Run is deployed)

   gcloud projects add-iam-policy-binding ${PROJECT_ID} --member="serviceAccount:${SA_EMAIL}" --role="roles/aiplatform.user"

   gcloud projects add-iam-policy-binding ${PROJECT_ID} --member="serviceAccount:${SA_EMAIL}" --role="roles/cloudtasks.admin"

   

   # 3. Service Account Token Creator and User role to the SA itself for signed URLs

   gcloud iam service-accounts add-iam-policy-binding ${SA_EMAIL} --member="serviceAccount:${SA_EMAIL}"  --role="roles/iam.serviceAccountTokenCreator" 

   gcloud iam service-accounts add-iam-policy-binding ${SA_EMAIL} --member="serviceAccount:${SA_EMAIL}"  --role="roles/iam.serviceAccountUser"
```
3. **GCSバケットの作成**:
```
export BUCKET_NAME="cloudgauge-reports-${PROJECT_ID}"

gsutil mb -p ${PROJECT_ID} gs://${BUCKET_NAME}

gcloud storage buckets add-iam-policy-binding gs://${BUCKET_NAME} --member="serviceAccount:${SA_EMAIL}" --role="roles/storage.objectAdmin"
```
---

### 

### **方法 1: ソースからデプロイ（推奨）**

### **ステップ 1: GitHubリポジトリをフォークする**

まず、ソースコードのコピーを作成します。

1. Navigate to the [CloudGauge GitHub repository](https://github.com/GoogleCloudPlatform/CloudGauge/).  
2. Click the **Fork** button in the top-right corner of the page.  
3. Choose your GitHub account as the destination for the fork. This will create a copy of the repository under your account (e.g., `https://github.com/your-username/CloudGauge`).

1. [CloudGauge GitHubリポジトリ](https://github.com/GoogleCloudPlatform/CloudGauge/)にアクセス。
2. ページ右上の **Fork** ボタンをクリック。
3. フォーク先として自分のGitHubアカウントを選択。これにより、自分のアカウント下にリポジトリのコピーが作成されます（例: `https://github.com/your-username/CloudGauge`）。


---

### **ステップ 2: Cloud Runサービスを作成する**

次に、Cloud Runサービスを作成し、新しいリポジトリに接続します。

1. Google Cloudコンソールで、**Cloud Run**ページを開く。
2. **サービスの作成**をクリック。
3. **Continuously deploy new revisions from a source repository** を選択し、**Set up with Cloud Build**をクリック。
4. 新しいパネルが表示された後、"Repository"の下にある"Source" セクションの**Manage connected repositories**をクリック。  
5. 新しいウィンドウが開き、GitHubに**Google Cloud Buildアプリをインストール**するように求められます。
    * GitHubのユーザー名または組織を選択します。
    * 「Repository access」セクションで、**All repositories**（すべてのリポジトリ）または**Only select repositories**（選択したリポジトリのみ）のいずれかを選択します。後者を選択した場合は、フォークした`CloudGauge`リポジトリを必ず選択してください。
    * **Install**（インストール）または**Save**（保存）をクリックします。
6. Cloudコンソールに戻り、新しく接続したフォーク済みリポジトリとブランチ（`main`）を選択して、**次へ（Next)**をクリック。
7. **Build Settings** にて以下を設定:
   * **Build Type**: `Dockerfile`を選択 
   * **Source location**: デフォルトの`/Dockerfile`  
   * **Save**をクリック  
9. サービスの詳細を設定します:
   * **Service name**: 例`cloudgauge-service`.  
   * **Region**: リージョンを選択
10. "Container(s), Volumes, Networking, Security"セクションを展開
   * **Identity & Security**タブにて、共通の前提条件のステップ２で作成したサービスアカウントを選択
   * **General**タブにて**Request Timeout**を`3600`秒に設定  
   * **Variables & Secrets**タブにて以下の**Environment Variables**を設定
     * `PROJECT_ID`: ご自身のGCP Project ID (例：`my-gcp-project`)  
     * `TASK_QUEUE`: `cloudgauge-scan-queue`  
     * `RESULTS_BUCKET`: ご自身のGCSバケット名 (例： `cloudgauge-reports-my-gcp-project`)  
     * `SERVICE_ACCOUNT_EMAIL`:サービスアカウントに紐づくemailアドレス
     * `LOCATION`: ステップ9で選択したリージョン (e.g., `asia-south1`)  
11. **Create**をクリック　ー ビルドとデプロイプロセスが開始します。

---

### **ステップ 3: 必要なIAMロールを付与する**
サービスアカウントにはCloud Runサービスに対して以下の権限付与が必要です。これの権限付与により、全ての権限が厳密にスコープ化されます（セキュリティのベストプラクティスが遵守されます）。

**Cloud Run 起動元 (roles/run.invoker)**: このロールは、Cloud TasksサービスがCloudGaugeサービスを安全にトリガーしてスキャンを開始できるようにするために必要です。この権限は、デプロイしたばかりの新しいCloud Runサービスに対して付与されます。

**Cloud Run 閲覧者 (roles/run.viewer)**: このロールにより、サービスは起動時に自身のパブリックURLを自動的に検出できます。この機能により、サービスを手動で自身のURLで更新する必要がなくなり、シングルステップでのデプロイが可能になります。この権限はサービスレベルで付与されます。

上記２つのロールを**サービスレベル**で付与することで、サービスアカウントがアクセスする必要のある特定のリソースに対してのみ、**最小限の権限**を持つよう設定可能となります。

**Cloud Shell**または`gcloud`がインストールされたローカルターミナルを開き、プレースホルダーをご実際の値に置き換えて以下のコマンドを実行。

```
# Store your service account email in a variable for convenience  
SA_EMAIL="cloudgauge-sa@your-project-id.iam.gserviceaccount.com"
SERVICE_NAME="your-chosen-service-name"
export REGION="asia-south1" # Or your chosen region

# Grants permission to be invoked by Cloud Tasks
gcloud run services add-iam-policy-binding ${SERVICE_NAME} --member="serviceAccount:${SA_EMAIL}" --role="roles/run.invoker" --region=${REGION}

# Grants permission to view its own service details to find its URL
gcloud run services add-iam-policy-binding ${SERVICE_NAME} --member="serviceAccount:${SA_EMAIL}" --role="roles/run.viewer" --region=${REGION}

```
以上でCloudGaugeの準備が整いました。URLにお進みいただければアプリケーションを利用開始できる状態となっています。

With these permissions set, your CloudGauge instance is fully deployed and ready to use. You can now proceed to the application's URL to start your first scan.

---

### **方法 2: gcloudを使用した手動ビルド＆デプロイ** 

この方法は、ビルドとデプロイの手順を手動で制御する方法となります。

1. **本リポジトリをクローンする:**:
```
git clone https://github.com/GoogleCloudPlatform/CloudGauge
cd cloudgauge
```
2. **環境変数を設定する**:  
   * （共通のセットアップで設定したPROJECT_IDとSA_EMAILと置き換えてください）
```
     export REGION="asia-south1" # Or your preferred region  
     export SERVICE_NAME="cloudgauge-service"  
     export BUCKET_NAME="cloudgauge-reports-${PROJECT_ID}"  
     export QUEUE_NAME="cloudgauge-scan-queue"
```   

3. **サービスをビルドしてデプロイする**:
   * このコマンドはコンテナをビルドし、デプロイします。
```
# Build the container image using Cloud Build  
gcloud builds submit . --tag "gcr.io/${PROJECT_ID}/${SERVICE_NAME}" --region=${REGION}

# Deploy to Cloud Run  
gcloud run deploy ${SERVICE_NAME} \
  --image "gcr.io/${PROJECT_ID}/${SERVICE_NAME}" \
  --service-account ${SA_EMAIL} \
  --region ${REGION} \
  --allow-unauthenticated \
  --platform managed \
  --timeout=3600 \
  --memory=1Gi \
  --set-env-vars=PROJECT_ID=${PROJECT_ID},TASK_QUEUE=${QUEUE_NAME},RESULTS_BUCKET=${BUCKET_NAME},SERVICE_ACCOUNT_EMAIL=${SA_EMAIL},LOCATION=${REGION}
```
4. **Invoker & Viewer権限を付与する:**:  
   * 立ち上げたサービスのSAに、呼び出し権限を付与します。
```
gcloud run services add-iam-policy-binding ${SERVICE_NAME} \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/run.invoker" \
  --region=${REGION}

gcloud run services add-iam-policy-binding ${SERVICE_NAME} \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/run.viewer" \
  --region=${REGION}
```

以上でサービスのデプロイと設定は完了となります

## **How to Use** 

1. Navigate to your service's URL (`${SERVICE_URL}`).  
2. Select your Scope from Dropdown menu : Organization, Folder or Project
3. Select the resource from the Dropdown
4. Click "Start Scan".  
5. You will be redirected to a status page. Wait for the scan to complete (this can take 5-15 minutes depending on org size).  
6. Once finished, links to the **Interactive HTML Report** and **Download CSV Report** will appear.

## **Troubleshooting**

If the status page is stuck for a long time, the background worker is likely failing.

### **Step 1: Check the Cloud Run Logs**

1. Go to the **Cloud Run** page in the Google Cloud Console.  
2. Click on your service (`cloudgauge-service`).  
3. Go to the **LOGS** tab.  
4. Look for log entries for requests made to the `/run-scan` URL.  
5. If you see logs for `/run-scan`, look for any errors in red.

### **Step 2: Check the Cloud Tasks Logs**

1. Go to the **Cloud Tasks** page in the Google Cloud Console.  
2. Click on your queue (`cloudgauge-scan-queue`).  
3. Go to the **LOGS** tab.  
4. Look at the status of the task attempts. If you see a `PERMISSION_DENIED` (HTTP 403\) error, it means you missed the **"Grant Invoker Permission"** step.

### **Step 3: Resolve Common Errors**

#### **Memory Limit Exceeded**

* **Error Message**: You might see an error in the Cloud Run logs that says: “`Memory limit of 512 MiB exceeded …”`  
* **Cause**: The scan process is using more memory than the default amount allocated to the Cloud Run service.  
* **Solution**: You need to increase the memory allocated to your service.  
  * **Via Console**:  
    1. Click **"Edit & Deploy New Revision"** on your Cloud Run service page.  
    2. Under the "General" tab, find **"Memory allocation"** and increase it (e.g., to `2 GiB`).  
    3. Click **Deploy**.  
  * **Via gcloud CLI**:

```
gcloud run services update cloudgauge-service \
  --memory=2Gi \
  --region=<your-region>
```
    
---

#### **Permission Denied on Google Cloud APIs**

* **Error Message**: The logs show a `PERMISSION_DENIED` error related to a specific Google Cloud service, such as `storage.googleapis.com` or `iam.googleapis.com`.  
* **Cause**: The service account (`cloudgauge-sa@...`) is missing an IAM role needed to access a specific API.  
* **Solution**: The error message will usually state which permission is missing. Go back to the **"Common Prerequisites"** section of the deployment instructions and verify that all `gcloud ... add-iam-policy-binding` commands were run successfully against the correct service account. You may need to re-run the command for the missing role.

---

#### **Container Failed to Start**

* **Error Message**: The Cloud Run revision is not becoming healthy, and the logs show an error right at startup, such as `ModuleNotFoundError` in Python or an error about a missing environment variable.  
* **Cause**: This typically happens for one of two reasons:  
  1. An environment variable was not set correctly.  
  2. There is a bug in the application code or a missing dependency in `requirements.txt`.  
* **Solution**:  
  1. Check the **LOGS** tab for the specific error message that occurs when the container tries to start.  
  2. If the error is related to a variable, click **"Edit & Deploy New Revision,"** go to the **"Variables & Secrets"** tab, and ensure all required variables (`PROJECT_ID`, `WORKER_URL`, etc.) are present and have the correct values.  
  3. If it is a code error, you will need to fix the source code and deploy a new revision.

---

#### **Request Timeout**

* **Error Message**: The logs show an HTTP `504` status code or a message like "The request has been terminated because it has reached its deadline."  
* **Cause**: The scan is taking longer to complete than the configured request timeout on the Cloud Run service.  
* **Solution**: The deployment instructions recommend a timeout of `3600` seconds (1 hour). Verify this was set correctly.  
  * **Via Console**: Go to **"Edit & Deploy New Revision"** and check the **"Request timeout"** value under the "General" tab.  
  * **Via gcloud CLI**: You can update the service with the correct timeout using:

```
gcloud run services update cloudgauge-service \
  --timeout=3600 \
  --region=<your-region>
```
---

#### **Builds Fail in a VPC Service Controls Environment**

* **Symptom:** When running a Cloud Build, the process fails during steps that require fetching external packages (e.g., `pip install`, `apt-get update`, or `npm install`). You may see timeout errors or messages related to network connectivity and egress being blocked.  
* **Cause:** By default, Cloud Build runs on workers in a Google-managed project that is outside your organization's VPC Service Controls (VPC SC) perimeter. Your perimeter is correctly blocking egress traffic from these external workers, preventing them from accessing public repositories to download dependencies.  
* **Solution:** Use **Cloud Build private pools**. This provisions dedicated build workers that run *inside* your own VPC network, making all build traffic internal and compliant with your security perimeter.  
    
  **1\. Create a Private Pool in Your VPC:** First, create a private worker pool connected to your VPC network. This ensures all build steps are executed within your perimeter.
```
gcloud builds worker-pools create [POOL_NAME] \
    --project=[PROJECT_ID] \
    --region=[REGION] \
    --peered-network=projects/[PROJECT_ID]/global/networks/[VPC_NETWORK]
```
  *Replace `[POOL_NAME]`, `[PROJECT_ID]`, `[REGION]`, and `[VPC_NETWORK]` with your specific values.*  

  
    
  **2\. Configure a Secure Egress Route for the Private Pool**

A private pool inside a VPC SC perimeter cannot access public package repositories by default. You need to provide a route to the internet.

**Note:** **Cloud NAT will not work for this use case.** Private pools reside in a separate, Google-managed VPC peered to yours. Cloud NAT does not provide service across a VPC peering connection.

The recommended solution is to use a **dedicated Compute Engine VM as a secure NAT Gateway**.

1. **Create a NAT Gateway VM:** Provision a small Compute Engine VM within your VPC. This VM should have an external IP address and be configured to perform network address translation (masquerading). You can use a startup script to enable IP forwarding and set the necessary iptables rules.  
2. **Create Custom Routes:** You must create custom routes to direct traffic from your private pool's IP range to the NAT gateway VM. This ensures only the build workers' traffic is routed for external access, leaving other resources unaffected.  
3. **Configure Firewall Rules:** Create VPC firewall rules to:  
   * Allow **ingress** traffic from the private pool's IP range to the NAT gateway VM.  
   * Allow **egress** traffic from the NAT gateway VM to the internet (0.0.0.0/0).
    
  **3\. Run Your Build Using the Private Pool:** Modify your `gcloud builds submit` command to include the `--worker-pool` flag, pointing it to your newly created private pool.

```
gcloud builds submit . \
  --tag "gcr.io/[PROJECT_ID]/[SERVICE_NAME]" \
  --region=[REGION] \
  --worker-pool=projects/[PROJECT_ID]/locations/[REGION]/workerPools/[POOL_NAME]
```

This command now directs Cloud Build to use a worker from your internal pool. The worker's traffic is routed through your secure NAT Gateway VM, allowing it to fetch external dependencies while remaining fully compliant with your VPC SC perimeter.

---

### **Forcing Image Storage to a Specific Region**

**Symptom:** You need to store your container images in a specific Google Cloud region (e.g., asia-south1 for organization policy resource location constraints), but by default, gcr.io hosts images in multi-regional locations (us, eu, asia) and does not offer specific regional control.

**Cause:** Google Container Registry (gcr.io) is a multi-regional service. To gain fine-grained control over the storage location of your images, you should use **Artifact Registry**, which is Google Cloud's recommended service for managing container images and language packages.

**Solution:** Create a Docker repository in Artifact Registry in your desired region and update your build commands to point to the new regional endpoint.


**Step 1: Create a Regional Artifact Registry Repository**

First, create a new Docker-format repository in your chosen region. This example uses asia-south1 (Mumbai).

```
gcloud artifacts repositories create cloudgauge-repo \ 
    --repository-format=docker \
    --location=asia-south1 \
    --description="CloudGauge Docker repository in Mumbai"
```

*You only need to run this command once to set up the repository.*


**Step 2: Update Your Build and Push Commands**

Next, you must change the image path in your build and push commands from gcr.io/... to the new Artifact Registry path. The new format is \[REGION\]-docker.pkg.dev/\[PROJECT\_ID\]/\[REPO\_NAME\]/\[IMAGE\_NAME\].

#### **Option A: Using Cloud Build**

If you're using Cloud Build, update the \--tag flag in your gcloud builds submit command:

```
gcloud builds submit . --tag "asia-south1-docker.pkg.dev/[PROJECT_ID]/cloudgauge-repo/[SERVICE_NAME]"
```

#### **Option B: Pushing a Local Image**

If you are building your image locally, update your docker tag and docker push commands:

\# 1\. Build the image 
```
docker build -t cloudgauge-image .
```
\# 2\. Tag the image for your new Artifact Registry repo 
```
docker tag cloudgauge-image asia-south1-docker.pkg.dev/[PROJECT_ID]/cloudgauge-repo/cloudgauge-image
```
\# 3\. Push the image  
```
docker push asia-south1-docker.pkg.dev/[PROJECT_ID]/cloudgauge-repo/cloudgauge-image
```
By following these steps, you can ensure your container images are stored and managed in the specific Google Cloud region that meets your requirements.

---

## **Cleanup Script**

This gCloud script will remove all the resources created by the tool. 

### **Configure Your Variables**

Before running the script, replace the placeholder values in the first few lines with the ones you used during deployment.

```
#!/bin/bash

# --- CONFIGURE THESE VARIABLES ---
export YOUR_ORG_ID="123456789012" # Replace with your Organization ID
export PROJECT_ID="your-gcp-project-id"   # Replace with your Project ID
export REGION="asia-south1"         # Replace with the region you deployed to
# --- END CONFIGURATION ---


# Set derived variables
export SERVICE_NAME="cloudgauge-service"
export QUEUE_NAME="cloudgauge-scan-queue"
export BUCKET_NAME="cloudgauge-reports-${PROJECT_ID}"
export SA_NAME="cloudgauge-sa"
export SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

# --- DELETION SCRIPT STARTS HERE ---

echo "--- Starting Cleanup for CloudGauge in project ${PROJECT_ID} ---"

# 1. Delete the Cloud Run service
echo "Deleting Cloud Run service: ${SERVICE_NAME}..."
gcloud run services delete ${SERVICE_NAME} --region=${REGION} --platform=managed --quiet

# 2. Delete the Cloud Tasks queue
echo "Deleting Cloud Tasks queue: ${QUEUE_NAME}..."
gcloud tasks queues delete ${QUEUE_NAME} --location=${REGION} --quiet

# 3. Delete the GCS bucket and all its contents
echo "Deleting GCS bucket: gs://${BUCKET_NAME}..."
gsutil -m rm -r "gs://${BUCKET_NAME}"

# 4. Delete the container image from GCR
echo "Deleting container image..."
gcloud container images delete "gcr.io/${PROJECT_ID}/${SERVICE_NAME}" --force-delete-tags --quiet

# 5. Remove all IAM policy bindings for the service account
echo "Removing IAM bindings for ${SA_EMAIL}..."

# Organization-level roles
gcloud organizations remove-iam-policy-binding ${YOUR_ORG_ID} --member="serviceAccount:${SA_EMAIL}" --role="roles/cloudresourcemanager.organizationViewer" --quiet
gcloud organizations remove-iam-policy-binding ${YOUR_ORG_ID} --member="serviceAccount:${SA_EMAIL}" --role="roles/iam.securityReviewer" --quiet
gcloud organizations remove-iam-policy-binding ${YOUR_ORG_ID} --member="serviceAccount:${SA_EMAIL}" --role="roles/recommender.organizationViewer" --quiet
gcloud organizations remove-iam-policy-binding ${YOUR_ORG_ID} --member="serviceAccount:${SA_EMAIL}" --role="roles/cloudasset.viewer" --quiet

# Project-level roles
gcloud projects remove-iam-policy-binding ${PROJECT_ID} --member="serviceAccount:${SA_EMAIL}" --role="roles/cloudtasks.admin" --quiet
gcloud projects remove-iam-policy-binding ${PROJECT_ID} --member="serviceAccount:${SA_EMAIL}" --role="roles/storage.objectAdmin" --quiet
gcloud projects remove-iam-policy-binding ${PROJECT_ID} --member="serviceAccount:${SA_EMAIL}" --role="roles/iam.serviceAccountTokenCreator" --quiet
gcloud projects remove-iam-policy-binding ${PROJECT_ID} --member="serviceAccount:${SA_EMAIL}" --role="roles/aiplatform.user" --quiet
gcloud projects remove-iam-policy-binding ${PROJECT_ID} --member="serviceAccount:${SA_EMAIL}" --role="roles/run.invoker" --quiet # This was added to the SA itself, but good to be explicit

# 6. Delete the Service Account
echo "Deleting service account: ${SA_EMAIL}..."
gcloud iam service-accounts delete ${SA_EMAIL} --quiet

echo "✅ Cleanup complete!"
```
---

### **Step-by-Step Explanation**

Here's a breakdown of what each command in the script does:

1. **Delete Cloud Run Service**: `gcloud run services delete`  
   * This removes the main web application itself, stopping it from running and incurring costs.  
2. **Delete Cloud Tasks Queue**: `gcloud tasks queues delete`  
   * Your script automatically creates a Cloud Tasks queue named `cloudgauge-scan-queue`. This command deletes that queue.  
3. **Delete GCS Bucket**: `gsutil -m rm -r`  
   * This command deletes the `cloudgauge-reports-...` bucket and all the HTML/CSV reports stored inside it. The `-m` flag helps it run faster if there are many report files.  
4. **Delete Container Image**: `gcloud container images delete`  
   * When you deployed the service, Cloud Build created a container image and stored it in Google Container Registry (GCR). This command deletes that stored image to keep your registry clean.  
5. **Remove IAM Bindings**: `gcloud ... remove-iam-policy-binding`  
   * This is a critical step. Before deleting the service account, you should remove all the permissions (roles) you granted it at both the **Organization** and **Project** levels. This prevents "ghost" principals from showing up in your IAM policies.  
6. **Delete Service Account**: `gcloud iam service-accounts delete`  
   * This is the final step. After removing its permissions, you can safely delete the `cloudgauge-sa` service account itself.


## **License & Support** 

This is not an officially supported Google product. This project is not eligible for the [Google Open Source Software Vulnerability Rewards Program](https://bughunters.google.com/open-source-security).

This project is licensed under the Apache 2.0 License. See the `LICENSE` file for details.

For issues or feature requests, please file an issue on the project's GitHub page.
