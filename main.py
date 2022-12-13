import numpy as np
import pandas as pd
from pandas import Timestamp
import matplotlib.pyplot as plt
from sklearn import svm
from sklearn.svm import SVC
from sklearn.preprocessing import MinMaxScaler
from sklearn.metrics import classification_report, confusion_matrix ,accuracy_score ,plot_roc_curve,roc_auc_score,roc_curve
from sklearn.model_selection import train_test_split
from sklearn.model_selection import train_test_split
import seaborn as sns
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import GridSearchCV
import matplotlib.gridspec as gridspec
from sklearn.preprocessing import StandardScaler


print(svm==SVC)
data_Train =pd.read_csv('KDDTrain+.txt')
data_Test=pd.read_csv('KDDTest+.txt')
columns = (['duration','protocol_type','service','flag','src_bytes','dst_bytes','land','wrong_fragment','urgent'
            ,'hot','num_failed_logins','logged_in','num_compromised','root_shell','su_attempted','num_root'
            ,'num_file_creations','num_shells','num_access_files','num_outbound_cmds','is_host_login'
            ,'is_guest_login','count','srv_count','serror_rate','srv_serror_rate','rerror_rate','srv_rerror_rate'
            ,'same_srv_rate','diff_srv_rate','srv_diff_host_rate','dst_host_count','dst_host_srv_count'
            ,'dst_host_same_srv_rate','dst_host_diff_srv_rate','dst_host_same_src_port_rate'
            ,'dst_host_srv_diff_host_rate','dst_host_serror_rate','dst_host_srv_serror_rate','dst_host_rerror_rate'
            ,'dst_host_srv_rerror_rate','attack','outcome'])
data_Train.columns=columns#加上标签
data_Test.columns=columns
data_Train.drop(columns='outcome',axis=1, inplace=True )#去掉outcome标签
data_Test.drop(columns='outcome',axis=1,inplace=True )

#测试训练集和测试集是否有空数据
print("-----------------------训练集空数据数量-----------------------")
print(data_Train.isnull().sum())
print("-----------------------测试集空数据数量-----------------------")
print(data_Test.isnull().sum())



#绘图




#攻击分为是和不是两类
attack_n_train = []
attack_n_test=[]


for i in data_Train.attack :#0代表不是攻击，1代表攻击
  if i == 'normal':
    attack_n_train.append(0)
  else:
    attack_n_train.append(1)
data_Train['attack'] = attack_n_train









for i in data_Test.attack :
  if i == 'normal':
    attack_n_test.append(0)
  else:
    attack_n_test.append(1)
data_Test['attack']=attack_n_test


#查看攻击和非攻击的数量
x_data = ["KDDTrain normal","KDDTrain attack","KDDTest normal","KDDTest attack"]
y_data = [data_Train['attack'].value_counts()[0],data_Train['attack'].value_counts()[1],data_Test['attack'].value_counts()[0],data_Test['attack'].value_counts()[1]]

# 正确显示中文和负号
plt.rcParams["font.sans-serif"] = ["SimHei"]
plt.rcParams["axes.unicode_minus"] = False

# 生成攻击与非攻击数量的统计图
for i in range(len(x_data)):
	plt.bar(x_data[i], y_data[i])

plt.title("攻击与非攻击数量统计")

plt.xlabel("类型")

plt.ylabel("数量")

f = plt.gcf()
f.savefig('attack num')
f.clear()

#编码字符串数据
data_Train['protocol_type'] = LabelEncoder().fit_transform(data_Train['protocol_type'])
data_Train['service'] = LabelEncoder().fit_transform(data_Train['service'])
data_Train['flag'] = LabelEncoder().fit_transform(data_Train['flag'])

data_Test['protocol_type'] = LabelEncoder().fit_transform(data_Test['protocol_type'])
data_Test['service'] = LabelEncoder().fit_transform(data_Test['service'])
data_Test['flag'] = LabelEncoder().fit_transform(data_Test['flag'])







y_train = data_Train['attack'].copy()
y_test=data_Test['attack'].copy()
x_train = data_Train.drop(['attack'], axis=1)
x_test=data_Test.drop(['attack'],axis=1)

print(len(x_train))
print(len(x_test))


scalar=StandardScaler()
x_train=scalar.fit_transform(x_train)
x_test = scalar.fit_transform(x_test)







param_grid = {'C': [0.2,0.5,1], 'gamma': [0.5],'kernel': ['rbf','poly','linear']}
grid = GridSearchCV(SVC(),param_grid ,verbose=2, cv= 3,refit=False)
grid.fit(x_train,y_train)


print(grid.best_params_)

rbf_svc = svm.SVC(kernel=grid.best_params_['kernel'], gamma=grid.best_params_['gamma'], C=grid.best_params_['C']).fit(x_train, y_train)
Y_pred_rbf =rbf_svc.predict(x_test)


accuracy_train=rbf_svc.score(x_train, y_train)
accuracy_test=rbf_svc.score(x_test, y_test)
print("accuracy KDDTrain:"+str(accuracy_train))
print("accuracy KDDTest:"+str(accuracy_test))
print("------------------------------------------------")
print( "accuracy  : " + str(np.round(accuracy_score(y_test,Y_pred_rbf),3)))


#绘图
x_data = ["KDDTrain","KDDTest"]
y_data = [accuracy_train,accuracy_test]

# 正确显示中文和负号
plt.rcParams["font.sans-serif"] = ["SimHei"]
plt.rcParams["axes.unicode_minus"] = False


for i in range(len(x_data)):
	plt.bar(x_data[i], y_data[i])

plt.title("准确率测试")

plt.xlabel("测试数据集")

plt.ylabel("准确率")

f = plt.gcf()
f.savefig('accuracy')
f.clear()