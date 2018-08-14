<template>
    <div class="layout">
        <Layout>
            <Header :style="{position: 'fixed', width: '100%', padding: '0px 50px 0px 0px'}">
                <div class='logo'></div>
                header text
            </Header>
            <Layout>
                <Sider width=64 :style="{position: 'fixed', height: '100%', top: '64px'}">
                    <div class='sider-item-list'>
                        <div class='sider-item'>
                            <div class='sider-item-icon'><Icon size=40 type="ios-arrow-dropleft-circle" /></div>
                            <div class='sider-item-text'><h2><a href="http://www.qq.com">nihao</a></h2></div>
                        </div>
                    </div>
                </Sider>
                <Layout>
                    <Content :style="{margin: '88px 0 0 88px', background: '#fff', minHeight: '500px'}">
                        <p>something</p>
                    </Content>
                    <Footer class="layout-footer-center">
                        2018-2018 &copy; Shuobu
                    </Footer>
                </Layout>
            </Layout>
        </Layout>
    </div>
</template>
<style scoped>
    .layout {
        background: #f5f7f9;
        position: relative;
        overflow: auto;
    }
    .logo {
        width: 64px;
        height: 64px;
        background: #495090;
        position: relative;
    }
    .sider-item-list {
        width: 100%;
        height: 100%;
        top: 64px;
    }
    .sider-item {
        width: 100%;
        height: 64px;
        background: blue;
        position: relative;
    }
    .sider-item-icon {
        height: 40;
    }
    .sider-item-text {
        height: 24;
    }
    .layout-footer-center {
        text-align: center;
    }
</style>
<script>
    export default {
    }
</script>
